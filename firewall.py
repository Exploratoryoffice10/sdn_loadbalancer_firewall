from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.addresses import EthAddr

rules = [['00:00:00:00:00:01','00:00:00:00:00:04'],['00:00:00:00:00:02', '00:00:00:00:00:04'],['00:00:00:00:00:03','00:00:00:00:00:08'],['00:00:00:00:00:05','00:00:00:00:00:07']]
# h1 h4   h2 h4   h3 h8        h5 h7

class SDNFirewall (EventMixin):
    
    def __init__ (self):
        self.listenTo(core.openflow)
        
    def _handle_ConnectionUp (self, event):
        for srd in rules:
            block = of.ofp_match()
            block.dl_src = EthAddr(srd[0])
            block.dl_dst = EthAddr(srd[1])
            flow_mod = of.ofp_flow_mod()
            flow_mod.match = block
            event.connection.send(flow_mod)
        
def launch ():
    core.registerNew(SDNFirewall)
    