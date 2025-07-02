# 🛠️ RedHelper - Automated Red Team Engagement Script

**RedHelper** is an end-to-end red team automation tool that assists with recon, Kerberoasting, hash cracking, SMB exploitation, BloodHound data collection, and privilege escalation — all while respecting stealth levels.

---

## 🚩 Features

✅ Automates common red team post-auth attack chain:
- ✅ SMB credential validation
- ✅ Nmap scanning (stealth-aware)
- ✅ SPN detection and Kerberoasting
- ✅ Hash extraction and cracking with Hashcat
- ✅ Automatic `psexec.py` execution with cracked credentials
- ✅ BloodHound collection via SharpHound (upload + execute)
- ✅ Basic privilege escalation data collection

---

## 🧤 Stealth Mode
**if it shows stealth mode not working try to change --stealth 1

Set using `--stealth 0|1|2|3`.

---

## 🗂️ Output & Loot

All results are saved under a directory named by target IP:

```
loot_<target_ip>/
├── nmap.txt              # Port scan results
├── smb_enum.txt          # SMB shares enumeration
├── roast.txt             # SPN hash output (Kerberoast)
├── cracked.txt           # Cracked hashes from hashcat
├── psexec_cracked.txt    # Psexec results from cracked creds
├── bloodhound.txt        # SharpHound execution output
├── privesc.txt           # Output of whoami /priv & local admins
└── summary.txt           # 🚩 Summary of everything
```

The script auto-generates a **summary file** with all findings and cracked credentials.

---

## ⚙️ Usage

```bash
python3 redhelper.py \
  --target 192.168.112.130 \
  --domain lab.local \
  --user SQLUser \
  --password 'P@ssword123' \
  --stealth 1 \
  --bloodhound
```

---

## 🔐 Requirements

- Python 3
- [Impacket](https://github.com/fortra/impacket) (clone to `/opt/impacket`)
- Hashcat
- SharpHound.exe (must be in same directory)

Install Impacket:
```bash
git clone https://github.com/fortra/impacket.git /opt/impacket
cd /opt/impacket && pip install .
```

---

## 📝 Notes

- If using NTLM hash instead of password, use `--hash` instead of `--password`
- SharpHound output is saved to: `C:\Users\Public\loot.zip` on the target
- Script automatically uploads `SharpHound.exe` to `C:\Windows\Temp\` before execution
- All commands are wrapped in stealth-aware delays

If it stuck somewhere here Press enter

[*] Opening SVCManager on 192.168.112.130.....
[*] Stopping service UMUU.....
[*] Removing service UMUU.....
[*] Removing file NTTryBcA.exe.....

---

## 🙌 Author

Developed by red team automation enthusiasts to simplify common attack chains.

🌍 medium.com/@psydck

---
