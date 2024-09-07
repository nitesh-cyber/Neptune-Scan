# Neptune Scan

**Neptune Scan** ek advanced port scanning tool hai jo Nmap se takra sakta hai. Yeh tool network security assessments ke liye design kiya gaya hai aur isme multiple features hain jo port scanning, service detection, OS fingerprinting, aur firewall detection cover karte hain.

## Features

- **SYN Scan (Stealth Scan):** Fast aur stealthy port scanning.
- **UDP Scan:** UDP ports ki scanning.
- **Service Detection:** Service banners aur versions ka detection.
- **Operating System Fingerprinting:** Target ke operating system ka guess.
- **Traceroute:** Network path analysis.
- **Firewall Detection:** Firewalls aur IDS ke presence ko detect karna.
- **Multithreading:** Faster scanning ke liye parallel threads ka use.

## Usage

Neptune Scan script ko run karne ke liye, yeh command use karein:

```bash
python neptune_scan.py [OPTIONS] TARGET_IP PORT_RANGE


# Neptune-Scan
