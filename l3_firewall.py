from os import error
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr, IPAddr
import csv

filepath=""

log = core.getLogger()

def read_rule_file(fp):
    rv = list()
    with open(fp,"r") as file:
        fr = csv.reader(file)
        for x in fr:
            rv.append(tuple(x))
            return rv 


class L3_Firewall(EventMixin):
    def __init__ (self):
        self.listenTo(core.openflow)
        log.info("Enabling Firewall Module")
        # Our firewall table
        self.firewall = {}

    def create_rule(self,src,dst,duration=0):
        ofm = of.ofp_flow_mod()
        ofp = of.ofp_match()
        ofp.nw_src = IPAddr(src)
        ofp.nw_dst = IPAddr(dst)
        ofm.idle_timeout = duration
        ofm.hard_timeout = duration
        self.connection.send(ofm)

    def add_rule(self,src,dst,event): 
        if (src,dst) in self.firewall:  
            log.info("RULE: DROP %s - %s already installed on switch %s",src,dst,dpidToStr(event.dpid))
        else:
            log.info("INSTALLING RULE: DROP %s - %s on switch %s",src,dst,dpidToStr(event.dpid))
            self.add_rule(src,dst,OFP_FLOW_PERMANENT)
            
    def delete_rule(self,src,dst):
        try: 
            del self.firewall[(src,dst)]
            log.info("Rule %s - %s deleted")
        except:
            log.info("no such rule")
            
            
    def _handle_connectionUp(self,event):
        self.connection = event.connection
        rules = read_rule_file(filepath)
        for x,y in rules:
            self.add_rule(x,y,event)
        log.info("firewall rules installed on switch %s",dpidToStr(event.dpid))        








def launch():
	core.registerNew(L3_Firewall)