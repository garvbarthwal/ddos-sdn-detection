from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel

class custom_topo(Topo):
    def build(self):
        # Adding Switches
        s1=self.addSwitch('s1')       
        s2=self.addSwitch('s2')
        s3=self.addSwitch('s3')

        #Adding Hosts
        h1=self.addHost('h1', ip="10.0.0.1/24")
        h2=self.addHost('h2', ip="10.0.0.2/24")
        h3=self.addHost('h3', ip="10.0.0.3/24")
        h4=self.addHost('h4', ip="10.0.0.4/24")
        h5=self.addHost('h5', ip="10.0.0.5/24")

        #Adding Links 
        self.addLink(h1, s1)
        self.addLink(h2, s1) # attacker

        self.addLink(h3, s2) # normal user
        self.addLink(h4, s2) # attacker
        
        self.addLink(h5, s3) # victim server

        self.addLink(s1, s3)
        self.addLink(s2, s3)

topos = {"customtopo": (lambda: custom_topo())}

if __name__ == '__main__':
    setLogLevel('info')

    topo = custom_topo()
    net = Mininet(topo=topo, controller=None)

    # Add remote controller (e.g., Ryu on localhost:6653)
    c0 = RemoteController('c0', ip='127.0.0.1', port=6653)
    net.addController(c0)

    net.start()
    CLI(net)
    net.stop()
