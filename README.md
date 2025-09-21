# SEED Labs – Mitnick Attack (Roll No: 23i-2125)

## 📌 Overview

This repository contains my implementation and report for the **SEED Labs Mitnick Attack** (NetSec, FAST).
The lab demonstrates how Kevin Mitnick exploited weaknesses in **TCP/IP trust-based authentication** to spoof trusted servers, inject commands, and gain unauthorized access.

## 🛠️ Lab Setup

* **Environment**: SEED Ubuntu 20.04 on VirtualBox
* **Tools**: Docker, Docker-Compose, Scapy, tcpdump/Wireshark
* **Network Topology**:

  * Attacker: `10.9.0.1`
  * X-Terminal: `10.9.0.5`
  * Trusted Server: `10.9.0.6`

## ⚡ Tasks

### Task 1 – Simulated SYN Flooding

* Silenced the trusted server using SYN flooding.
* Cached its MAC in the X-Terminal using:

  ```bash
  arp -s 10.9.0.6 <MAC>
  docker stop trusted-server-10.9.0.6
  ```
* **Observation**: X-Terminal continued trusting cached MAC → enabling spoofing.

---

### Task 2 – Sniff & Spoof TCP Connections

**First Connection**

* Spoofed TCP handshake: `10.9.0.6:1023 → 10.9.0.5:514`.
* Injected rsh payload:

  ```python
  data = b"9090\x00seed\x00seed\x00touch /tmp/xyz\x00"
  ```
* Command executed → `/tmp/xyz` created.

**Second Connection**

* X-Terminal opened a second connection to port `9090`.
* Spoofed SYN+ACK, completing the handshake.
* Verified execution of injected command.

---

### Task 3 – Planting a Backdoor

* Modified payload to:

  ```bash
  echo + + > /home/seed/.rhosts; chmod 644 /home/seed/.rhosts
  ```
* Installed rsh client on attacker:

  ```bash
  apt-get install -y rsh-redone-client
  rsh 10.9.0.5 -l seed
  ```
* Achieved password-less login.

---

## 🔎 Observations

* **ARP caching** was essential for spoofing.
* **rsh required dual TCP connections** (data + stderr).
* Modern OSes use **randomized TCP sequence numbers** → blind spoofing is nearly impossible today.
* `.rhosts` backdoor showed why **rsh is obsolete** and replaced by SSH.

---

## ✅ Conclusion

This lab demonstrated:

1. SYN flooding for denial-of-service.
2. TCP handshake spoofing with Scapy.
3. Remote command injection and backdoor planting.

📖 **Key Lesson**: Trust-based authentication and predictable sequence numbers are **insecure**. Secure alternatives like **SSH** are mandatory in modern systems.

---

## 📂 Files in This Repo

* `spoof1.py` → Spoofs the first TCP connection
* `spoof_err.py` → Handles second connection (error port)
* `report.pdf` → Detailed report
* `slides.docx` → Step-by-step screenshots & code

---
