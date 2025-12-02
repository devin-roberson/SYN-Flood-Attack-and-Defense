import argparse
import time
import threading
from collections import defaultdict

class TokenBucket:
    def __init__(self, capacity, fill_rate):
        self.capacity = capacity
        self.fill_rate = fill_rate
        self.tokens = capacity
        self.last_update = time.time()
        self.lock = threading.Lock()

    def _add_tokens(self):
        now = time.time()
        elapsed = now - self.last_update
        self.tokens = min(self.capacity, self.tokens + elapsed * self.fill_rate)
        self.last_update = now

    def consume(self, tokens=1):
        with self.lock:
            self._add_tokens()
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    def get_tokens(self):
        with self.lock:
            self._add_tokens()
            return self.tokens


class IPRateLimiter:
    def __init__(self, capacity=100, fill_rate=10, cleanup_interval=60):
        self.capacity = capacity
        self.fill_rate = fill_rate
        self.buckets = {}
        self.lock = threading.Lock()
        self.cleanup_interval = cleanup_interval
        self.last_cleanup = time.time()

    def _cleanup_old_buckets(self):
        now = time.time()
        if now - self.last_cleanup > self.cleanup_interval:
            with self.lock:
                # remove buckets that are at full capacity (idle)
                # create a copy of keys to avoid modifying dict during iteration
                idle_ips = [
                    ip for ip, bucket in list(self.buckets.items())
                    if bucket.get_tokens() >= self.capacity
                ]
                for ip in idle_ips:
                    del self.buckets[ip]
                self.last_cleanup = now

    def is_allowed(self, ip_address):
        self._cleanup_old_buckets()
        with self.lock:
            if ip_address not in self.buckets:
                self.buckets[ip_address] = TokenBucket(self.capacity, self.fill_rate)
        return self.buckets[ip_address].consume()

    def get_status(self, ip_address):
        with self.lock:
            if ip_address in self.buckets:
                return {
                    'ip': ip_address,
                    'tokens': self.buckets[ip_address].get_tokens(),
                    'capacity': self.capacity
                }
            return {
                'ip': ip_address,
                'tokens': self.capacity,
                'capacity': self.capacity
            }

    def get_all_status(self):
        with self.lock:
            return {
                ip: {
                    'tokens': bucket.get_tokens(),
                    'capacity': self.capacity
                }
                for ip, bucket in self.buckets.items()
            }


class SYNFloodDetector:
    def __init__(self, window_size=10, threshold=50):
        self.window_size = window_size
        self.threshold = threshold
        self.syn_counts = defaultdict(list)
        self.lock = threading.Lock()

    def record_syn(self, ip_address):
        now = time.time()
        with self.lock:
            cutoff = now - self.window_size
            self.syn_counts[ip_address] = [
                t for t in self.syn_counts[ip_address] if t > cutoff
            ]
            self.syn_counts[ip_address].append(now)
            return len(self.syn_counts[ip_address]) > self.threshold

    def get_suspicious_ips(self):
        now = time.time()
        cutoff = now - self.window_size
        suspicious = []
        with self.lock:
            for ip, timestamps in self.syn_counts.items():
                recent = [t for t in timestamps if t > cutoff]
                if len(recent) > self.threshold:
                    suspicious.append({
                        'ip': ip,
                        'count': len(recent),
                        'threshold': self.threshold
                    })
        return suspicious

    def clear_ip(self, ip_address):
        with self.lock:
            if ip_address in self.syn_counts:
                del self.syn_counts[ip_address]


def demo_rate_limiter():
    """Demonstrate the rate limiter functionality."""
    print("=" * 60)
    print("Rate Limiter Demonstration")
    print("=" * 60)
    
    # Create a rate limiter with 10 tokens, 2 tokens/second refill
    limiter = IPRateLimiter(capacity=10, fill_rate=2)
    
    test_ip = "192.168.1.100"
    
    print(f"\n[*] Testing rate limiter for IP: {test_ip}")
    print(f"[*] Capacity: 10 tokens, Fill rate: 2 tokens/second")
    print()
    
    # Simulate rapid requests
    print("[*] Simulating 15 rapid requests:")
    for i in range(15):
        allowed = limiter.is_allowed(test_ip)
        status = "ALLOWED" if allowed else "BLOCKED"
        tokens = limiter.get_status(test_ip)['tokens']
        print(f"    Request {i+1}: {status} (tokens: {tokens:.2f})")
    
    print("\n[*] Waiting 3 seconds for token refill...")
    time.sleep(3)
    
    print("\n[*] Simulating 5 more requests:")
    for i in range(5):
        allowed = limiter.is_allowed(test_ip)
        status = "ALLOWED" if allowed else "BLOCKED"
        tokens = limiter.get_status(test_ip)['tokens']
        print(f"    Request {i+1}: {status} (tokens: {tokens:.2f})")
    
    print("\n" + "=" * 60)


def demo_flood_detector():
    """Demonstrate the SYN flood detector."""
    print("=" * 60)
    print("SYN Flood Detector Demonstration")
    print("=" * 60)
    
    detector = SYNFloodDetector(window_size=5, threshold=10)
    
    normal_ip = "192.168.1.1"
    attacker_ip = "10.0.0.100"
    
    print(f"\n[*] Window: 5 seconds, Threshold: 10 SYN packets")
    print()
    
    # Simulate normal traffic
    print(f"[*] Simulating normal traffic from {normal_ip} (5 SYNs):")
    for i in range(5):
        is_attack = detector.record_syn(normal_ip)
        print(f"    SYN {i+1}: Attack detected = {is_attack}")
    
    # Simulate attack traffic
    print(f"\n[*] Simulating attack traffic from {attacker_ip} (20 SYNs):")
    for i in range(20):
        is_attack = detector.record_syn(attacker_ip)
        if is_attack:
            print(f"    SYN {i+1}: *** ATTACK DETECTED ***")
        else:
            print(f"    SYN {i+1}: Normal")
    
    # Show suspicious IPs
    print("\n[*] Suspicious IPs:")
    for ip_info in detector.get_suspicious_ips():
        print(f"    {ip_info['ip']}: {ip_info['count']} SYNs (threshold: {ip_info['threshold']})")
    print("\n" + "=" * 60)

def main():
    parser = argparse.ArgumentParser(
        description="Rate Limiter and SYN Flood Detector Demonstration"
    )
    parser.add_argument(
        "--demo",
        choices=["rate-limiter", "flood-detector", "both"],
        default="both"
        help="Which demo to run (default: both)"
    )
    args = parser.parse_args()
    if args.demo in ["rate-limiter", "both"]:
        demo_rate_limiter()
        print()
    if args.demo in ["flood-detector", "both"]:
        demo_flood_detector()

if __name__ == "__main__":
    main()
