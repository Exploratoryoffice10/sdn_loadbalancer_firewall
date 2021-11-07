from mininet.topo import Topo

class TreeTopo(Topo):

    def __init__(self):
        Topo.__init__(self)
        h1 = self.addHost( 'h1', ip='10.0.0.1', mac='00:00:00:00:00:01' )
        h2 = self.addHost( 'h2', ip='10.0.0.2', mac='00:00:00:00:00:02' )
        h3 = self.addHost( 'h3', ip='10.0.0.3', mac='00:00:00:00:00:03' )
        h4 = self.addHost( 'h4', ip='10.0.0.4', mac='00:00:00:00:00:04' )
        h5 = self.addHost( 'h5', ip='10.0.0.5', mac='00:00:00:00:00:05' )
        h6 = self.addHost( 'h6', ip='10.0.0.6', mac='00:00:00:00:00:06' )
        h7 = self.addHost( 'h7', ip='10.0.0.7', mac='00:00:00:00:00:07' )
        h8 = self.addHost( 'h8', ip='10.0.0.8', mac='00:00:00:00:00:08' )
        h9 = self.addHost( 'h9', ip='10.0.0.9', mac='00:00:00:00:00:09' )

        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        s5 = self.addSwitch('s5')
        s6 = self.addSwitch('s6')
        s7 = self.addSwitch('s7')

        self.addLink(h1,s3)
        self.addLink(h2,s3)
        self.addLink(h3,s4)
        self.addLink(h4,s4)
        self.addLink(h5,s6)
        self.addLink(h6,s6)
        self.addLink(h7,s7)
        self.addLink(h8,s7)
        self.addLink(h9,s7)

        root = s1
        layer1 = [s2,s5]
        layer2 = [s3,s4,s6,s7]

        for idx,l1 in enumerate(layer1):
            self.addLink( root,l1 )
            self.addLink( l1, layer2[2*idx] )
            self.addLink( l1, layer2[2*idx + 1] )


topos = { 'mytopo': (lambda: TreeTopo() ) }