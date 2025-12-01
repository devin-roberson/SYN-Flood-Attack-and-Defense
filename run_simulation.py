from topology import create_topology
import time
import subprocess
import sys
from mininet.log import setLogLevel, info


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
        f"python3 attack/syn_flood.py "
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
    setLogLevel('info')

    info("*** Creating network\n")
    net = create_topology()
    net.start()

    attacker = net.get("attacker")
    victim = net.get("victim")
    client = net.get("client")

    info("*** Testing connectivity\n")
    net.pingAll()
    lower_defenses(victim)
    # Start webserver
    start_server(victim)

    # Client loading victim page normally
    info("*** Client fetching victim page before attack...\n")
    print(client.cmd("curl -s http://10.0.0.2:8080"))

    before = syn_count(victim)
    print(f"\n*** Before attack: SYN_RECV count = {before}")

    # Run SYN Flood
    run_attack(attacker, "10.0.0.2")

    after = syn_count(victim)
    print(f"\n*** After attack: SYN_RECV count = {after}")

    # Try fetching the page again
    info("*** Client attempting to fetch page after attack...\n")
    print(client.cmd("curl -s --max-time 2 http://10.0.0.2:8080"))

    info("*** Stopping network\n")
    net.stop()


if __name__ == "__main__":
    main()
