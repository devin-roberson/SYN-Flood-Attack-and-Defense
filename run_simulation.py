from topology import create_topology
import time
import subprocess
import sys
from mininet.log import setLogLevel, info
from defense.firewall_rules import *

def run_in_host(host, cmd):
    return host.cmd(cmd).strip()

def syn_count(victim):
    count = victim.cmd("ss -ant state syn-recv | wc -l").strip()
    try:
        count = int(count)
        return max(0, count - 1)
    except:
        return 0

def start_server(victim):
    info("*** Starting web server on victim at port 8080\n")
    victim.cmd("pkill -f http.server")  # cleanup old
    victim.cmd("python3 -m http.server 8080 >/dev/null 2>&1 &")
    time.sleep(1)
    # verify server
    out = victim.cmd("curl -s http://127.0.0.1:8080")
    if out:
        info("*** Web server OK\n")
    else:
        info("*** Warning: Web server may not have started\n")

def run_attack(attacker, target_ip):
    info("*** Launching SYN Flood attack…\n")
    cmd = (
        f"python3 syn_flood.py "
        f"-t {target_ip} -p 8080 -c 20000 "
    )
    output = attacker.cmd(cmd)
    info(output + "\n")

def lower_defenses(victim):
    info("*** Weakening victim TCP stack for simulation realism\n")
    victim.cmd("sysctl -w net.ipv4.tcp_syncookies=0")
    victim.cmd("sysctl -w net.ipv4.tcp_max_syn_backlog=4096")
    victim.cmd("sysctl -w net.ipv4.tcp_synack_retries=5")
    victim.cmd("sysctl -w net.ipv4.tcp_abort_on_overflow=0")
    victim.cmd("sysctl -w net.ipv4.tcp_timestamps=0")

def main():
    setLogLevel("info")

    net = create_topology()
    net.start()

    attacker = net.get("attacker")
    victim   = net.get("victim")
    client   = net.get("client")
    target_ip = "10.0.0.2"

    # ============================
    # SETUP
    # ============================
    clear_defenses(victim)
    lower_defenses(victim)
    start_server(victim)

    # ============================
    # PHASE 1 — NO DEFENSES
    # ============================
    print("\n========== PHASE 1: DEFENSES OFF ==========")

    before1 = syn_count(victim)
    print(f"[NO DEFENSES] SYN_RECV before attack: {before1}")

    run_attack(attacker, target_ip)

    after1 = syn_count(victim)
    print(f"[NO DEFENSES] SYN_RECV after attack: {after1}")

    print("[NO DEFENSES] Client test:")
    print(client.cmd(f"curl -s --max-time 2 http://{target_ip}:8080"))

    # ============================
    # APPLY DEFENSES
    # ============================
    apply_defenses(victim, logging=False)

    # ============================
    # PHASE 2 — DEFENSES ON
    # ============================
    print("\n========== PHASE 2: DEFENSES ON ==========")

    before2 = syn_count(victim)
    print(f"[DEFENSES ON] SYN_RECV before attack: {before2}")

    run_attack(attacker, target_ip)

    after2 = syn_count(victim)
    print(f"[DEFENSES ON] SYN_RECV after attack: {after2}")

    print("[DEFENSES ON] Client test:")
    print(client.cmd(f"curl -s --max-time 2 http://{target_ip}:8080"))

    # ============================
    # RESULTS
    # ============================
    print("\n========== COMPARISON ==========")
    print(f"No defenses SYN_RECV: {after1}")
    print(f"With defenses SYN_RECV: {after2}")

    net.stop()

if __name__ == "__main__":
    main()
