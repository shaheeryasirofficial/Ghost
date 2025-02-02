# GHOST - Advanced Python-Based Port Scanner  

**Version:** 1.0  
**Author:** Shaheer Yasir  
**Platform:** Windows (Executable: `ghost.exe`)  

## 🛠️ Overview  

**GHOST** is an advanced Python-based port scanner designed for penetration testers and cybersecurity professionals. It is compiled into an executable (`ghost.exe`) for ease of use on Windows systems. GHOST offers more than just port scanning—it integrates CVE vulnerability scanning, WAF detection, and intelligent fingerprinting to provide deep insights into a target system's security posture.  

## 🚀 Features  

- ✅ **Fast & Multi-threaded Port Scanning** – Scans thousands of ports rapidly using asynchronous requests.  
- ✅ **CVE Scanning & Exploit Discovery** – Checks services against known CVEs and publicly available exploits.  
- ✅ **WAF Detection** – Identifies web application firewalls (WAFs) to help in security assessments.  
- ✅ **Service Fingerprinting** – Determines running services, software versions, and potential vulnerabilities.  
- ✅ **Custom Scan Ranges** – Users can define specific ports or full-range scans for better control.  
- ✅ **Banner Grabbing** – Extracts service banners for further analysis.  
- ✅ **Stealth Mode** – Implements evasion techniques to reduce detection by IDS/IPS systems.  
- ✅ **Export Results** – Saves scan results in multiple formats (TXT, JSON, CSV).  

## 🏗️ Installation  

1. Download the latest release of `ghost.exe` from the [GitHub repository](https://github.com/shaheeryasirofficial/Ghost).  
2. Open a command prompt and navigate to the directory where `ghost.exe` is stored.  

## ⚡ Usage  

Run the executable with the desired options from the command line:  

```powershell
ghost.exe -t <target> -p <ports> [options]
