def detect_interface(host):
    """Detect the correct interface name inside a Mininet host."""
    interfaces = host.cmd("ls /sys/class/net").strip().split()
    # Pick the first non-loopback interface
    for iface in interfaces:
        if iface != "lo":
            return iface
    return "eth0"   # fallback

def enable_syn_cookies(victim):
    victim.cmd("sysctl -w net.ipv4.tcp_syncookies=1")
    print("[+] SYN cookies: enabled")

def disable_syn_cookies(victim):
    victim.cmd("sysctl -w net.ipv4.tcp_syncookies=0")
    print("[+] SYN cookies: disabled")

def set_syn_backlog(victim, size=4096):
    victim.cmd(f"sysctl -w net.ipv4.tcp_max_syn_backlog={size}")
    print(f"[+] SYN backlog set to: {size}")

def apply_rate_limit(victim, iface, rate="25/second", burst=50, logging=False):
    victim.cmd("iptables -F SYN_FLOOD 2>/dev/null")
    victim.cmd("iptables -X SYN_FLOOD 2>/dev/null")
    victim.cmd("iptables -N SYN_FLOOD")
    victim.cmd(
        f"iptables -A SYN_FLOOD -m limit --limit {rate} "
        f"--limit-burst {burst} -j RETURN"
    )

    # Optional logging
    if logging:
        victim.cmd("iptables -A SYN_FLOOD -j LOG --log-prefix 'SYN_DROP: '")

    victim.cmd("iptables -A SYN_FLOOD -j DROP")
    victim.cmd(f"iptables -I INPUT -i {iface} -p tcp --syn -j SYN_FLOOD")
    print(f"[+] SYN rate-limiting active ({rate}, burst={burst})")

def apply_conn_limit(victim, iface, limit=20):
    victim.cmd(
        f"iptables -A INPUT -i {iface} -p tcp "
        f"-m connlimit --connlimit-above {limit} -j DROP"
    )
    print(f"[+] Per-IP connection limit applied: {limit}")

def apply_invalid_drop(victim):
    victim.cmd("iptables -A INPUT -m state --state INVALID -j DROP")
    victim.cmd("iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP")
    victim.cmd("iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP")
    print("[+] Invalid / malformed TCP packets dropped")

def clear_defenses(victim):
    iface = detect_interface(victim)
    victim.cmd("iptables -F SYN_FLOOD 2>/dev/null")
    victim.cmd("iptables -X SYN_FLOOD 2>/dev/null")
    victim.cmd(f"iptables -D INPUT -i {iface} -p tcp --syn -j SYN_FLOOD 2>/dev/null")
    victim.cmd(
        f"iptables -D INPUT -i {iface} -p tcp "
        "--syn -m connlimit --connlimit-above 20 -j DROP 2>/dev/null"
    )
    victim.cmd("iptables -D INPUT -m state --state INVALID -j DROP 2>/dev/null")
    victim.cmd("iptables -D INPUT -p tcp --tcp-flags ALL ALL -j DROP 2>/dev/null")
    victim.cmd("iptables -D INPUT -p tcp --tcp-flags ALL NONE -j DROP 2>/dev/null")

    print("[+] All defense rules cleared")

def show_defenses(victim):
    rules = victim.cmd("iptables -L -n -v")
    print("\n========== IPTABLES RULES ==========")
    print(rules)
    print("====================================\n")

def apply_defenses(victim, logging=False):
    iface = detect_interface(victim)

    print("\n====================================")
    print("   Applying SYN Flood Defenses")
    print("====================================")

    enable_syn_cookies(victim)
    set_syn_backlog(victim, 4096)
    apply_invalid_drop(victim)
    apply_rate_limit(victim, iface, logging=logging)
    apply_conn_limit(victim, iface)

    print("====================================")
    print("      All Defenses Enabled")
    print("====================================\n")
