# HTB-CheatSheet

# Reconnaissance

## Nmap - Port Scanning

### [Nmap Cheat Sheet - TutorialsPoint](https://www.tutorialspoint.com/nmap-cheat-sheet)

### TCP and UDP Scan Examples

```bash
# Basic scan
sudo nmap -v -sS -sC -sV --top-ports 3500 {target_ip}

# Full scan
sudo nmap -v -sS -A -p- {target_ip}

# Use if no hosts respond to ping
sudo nmap -v -sS -Pn {target_ip}

# Use if SYN scan takes too long
nmap -v -sT -p- --min-rate 5000 --max-retries 1 {target_ip}

# UDP scan
nmap -v -sU -T4 --top-ports 100 {target_ip}
```

### NSE (Nmap Scripting Engine)

```bash
# Update system file database and search for NSE scripts
sudo updatedb
locate .nse | grep {script_name}

# Full vulnerability scan
# Warning: --script-args=unsafe=1 may cause issues on target systems
sudo nmap -v -sS -Pn --script=vuln --script-args=unsafe=1 {target_ip}
```

