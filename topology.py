from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo
from mininet.cli import CLI

class MyTopo(Topo):
    def build(self):
        # 🔥 FIXED MAC ADDRESSES
        h1 = self.addHost('h1', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', mac='00:00:00:00:00:02')
        h3 = self.addHost('h3', mac='00:00:00:00:00:03')
        h4 = self.addHost('h4', mac='00:00:00:00:00:04')

        # 🔥 OpenFlow 1.3 switches
        s1 = self.addSwitch('s1', protocols='OpenFlow13')
        s2 = self.addSwitch('s2', protocols='OpenFlow13')

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(s1, s2)
        self.addLink(h3, s2)
        self.addLink(h4, s2)

if __name__ == '__main__':
    net = Mininet(topo=MyTopo(), controller=None)

    net.addController('c0',
                      controller=RemoteController,
                      ip='127.0.0.1',
                      port=6653)

    net.start()
    CLI(net)
    net.stop()