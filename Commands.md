
# Neptune Scan Commands

**Neptune Scan** ek advanced port scanning tool hai. Yeh file Neptune Scan ke sabhi commands aur options ko detail mein explain karti hai.

## Command Syntax

```bash
python neptune_scan.py [OPTIONS] TARGET_IP PORT_RANGE
```

## Commands and Options

### **SYN Scan (Stealth Scan)**

- **Command:**
  ```bash
  python neptune_scan.py TARGET_IP PORT_RANGE
  ```
- **Description:**
  SYN scan perform karta hai, jo stealthy aur fast port scanning technique hai.

- **Example:**
  ```bash
  python neptune_scan.py 192.168.1.1 1-1024
  ```

### **UDP Scan**

- **Command:**
  ```bash
  python neptune_scan.py TARGET_IP PORT_RANGE --udp
  ```
- **Description:**
  UDP ports ki scanning perform karta hai.

- **Example:**
  ```bash
  python neptune_scan.py 192.168.1.1 1-1024 --udp
  ```

### **Service Detection**

- **Command:**
  ```bash
  python neptune_scan.py TARGET_IP PORT_RANGE --service-detect
  ```
- **Description:**
  Open ports pe service detection aur banner grabbing perform karta hai.

- **Example:**
  ```bash
  python neptune_scan.py 192.168.1.1 1-1024 --service-detect
  ```

### **Operating System Fingerprinting**

- **Command:**
  ```bash
  python neptune_scan.py TARGET_IP PORT_RANGE --os-fingerprint
  ```
- **Description:**
  Target ke operating system ka guess lagane ke liye OS fingerprinting perform karta hai.

- **Example:**
  ```bash
  python neptune_scan.py 192.168.1.1 1-1024 --os-fingerprint
  ```

### **Traceroute**

- **Command:**
  ```bash
  python neptune_scan.py TARGET_IP PORT_RANGE --traceroute
  ```
- **Description:**
  Target IP ke liye network path analysis (traceroute) perform karta hai.

- **Example:**
  ```bash
  python neptune_scan.py 192.168.1.1 1-1024 --traceroute
  ```

### **Firewall Detection**

- **Command:**
  ```bash
  python neptune_scan.py TARGET_IP PORT_RANGE --firewall-detect
  ```
- **Description:**
  Firewalls aur IDS ke presence ko detect karta hai aur unka behavior analyze karta hai.

- **Example:**
  ```bash
  python neptune_scan.py 192.168.1.1 1-1024 --firewall-detect
  ```

### **Verbose Output**

- **Command:**
  ```bash
  python neptune_scan.py TARGET_IP PORT_RANGE --verbose
  ```
- **Description:**
  Detailed output enable karta hai.

- **Example:**
  ```bash
  python neptune_scan.py 192.168.1.1 1-1024 --verbose
  ```

### **Multithreading**

- **Command:**
  ```bash
  python neptune_scan.py TARGET_IP PORT_RANGE --threads NUMBER
  ```
- **Description:**
  Scanning ko faster banane ke liye parallel threads ka use karta hai.

- **Example:**
  ```bash
  python neptune_scan.py 192.168.1.1 1-1024 --threads 10
  ```

### **Help**

- **Command:**
  ```bash
  python neptune_scan.py --help
  ```
- **Description:**
  Command-line options aur usage information display karta hai.

- **Example:**
  ```bash
  python neptune_scan.py --help
  ```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
