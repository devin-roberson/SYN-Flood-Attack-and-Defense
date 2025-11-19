from mininet.net import Mininet
from mininet.node import OVSBridge
from mininet.cli import CLI
from mininet.log import setLogLevel, info


def create_topology():
    net = Mininet(controller=None, switch=OVSBridge)
    s1 = net.addSwitch('s1')
    attacker = net.addHost('attacker', ip='10.0.0.1/24')
    victim = net.addHost('victim', ip='10.0.0.2/24')
    client = net.addHost('client', ip='10.0.0.3/24')
    net.addLink(attacker, s1)
    net.addLink(victim, s1)
    net.addLink(client, s1)
    return net

def run_topology():
    setLogLevel('info')
    net = create_topology()
    net.start()
    net.pingAll()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    run_topology()
