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
