from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str, str_to_dpid
from pox.lib.util import str_to_bool
from pox.lib.addresses import IPAddr
from pox.lib.packet import ipv4
import time,csv

_flood_delay = 0

filepath = "~/pox/pox/misc/rules.csv"

def read_rule_file(fp):
    rv = list()
    with open(fp,"r") as file:
        fr = csv.reader(file)
        for x in fr:
            rv.append(tuple(x))
            return rv 

log = core.getLogger()

class LearningSwitch (object):
    def __init__ (self, connection, transparent, blocked_protocols = [], blocked_ports = []):
        # Switch we'll be adding L2 learning switch capabilities to
        self.connection = connection    
        self.transparent = transparent
        self.macToPort = {}
        connection.addListeners(self)
        self.hold_down_expired = _flood_delay == 0
        self.blocked_protocols = blocked_protocols
        self.blocked_ports = blocked_ports
        log.debug("blocked protocols are %s"," ".join(self.blocked_protocols))
        log.debug("ports blocked are %s",self.blocked_ports[0])
        self.firewall = dict()  # add rules
        self.fw_tcp = [("10.0.0.1", "10.0.0.4")]
        self.fw_udp = [("10.0.0.2", "10.0.0.6")]
        self.fw_icmp = [("10.0.0.5", "10.0.0.8")]
        self.add_rules()

    def add_rules(self):
        if 't' in self.blocked_protocols:
            for src,dst in self.fw_tcp:
                self.firewall[("tcp", IPAddr(src), IPAddr(dst))] = True
        if 'u' in self.blocked_protocols:
            for src,dst in self.fw_udp:
                self.firewall[("udp", IPAddr(src), IPAddr(dst))] = True
        if 'i' in self.blocked_protocols:
            for src,dst in self.fw_icmp:
                self.firewall[("icmp", IPAddr(src), IPAddr(dst))] = True

    def _handle_PacketIn (self, event):
        packet = event.parsed
        def flood (message = None):
            msg = of.ofp_packet_out()
            if time.time() - self.connection.connect_time >= _flood_delay:
                if self.hold_down_expired is False:
                    self.hold_down_expired = True
                    log.info("%s: Flood hold-down expired -- flooding",
                        dpid_to_str(event.dpid))
                if message is not None: 
                    log.debug(message)
                msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            else:
                pass
            msg.data = event.ofp
            msg.in_port = event.port
            self.connection.send(msg)

        def drop (duration = None):
            if duration is not None:
                if not isinstance(duration, tuple):
                    duration = (duration,duration)
                msg = of.ofp_flow_mod()
                msg.match = of.ofp_match.from_packet(packet)
                msg.idle_timeout = duration[0]
                msg.hard_timeout = duration[1]
                msg.buffer_id = event.ofp.buffer_id
                self.connection.send(msg)
            elif event.ofp.buffer_id is not None:
                msg = of.ofp_packet_out()
                msg.buffer_id = event.ofp.buffer_id
                msg.in_port = event.port
                self.connection.send(msg)

        self.macToPort[packet.src] = event.port # 1
        
        # check before dropping packets
        if isinstance(packet.next,ipv4):
            if packet.find('tcp') is not None:  # tcp packets dropped
                if self.firewall.get(("tcp",packet.next.srcip,packet.next.dstip),False):
                    log.debug("blocked tcp packet from %s to %s",packet.next.srcip,packet.next.dstip)
                    drop()
                    return
            if packet.find('udp') is not None:  # udp packets dropped
                if self.firewall.get(("udp",packet.next.srcip,packet.next.dstip),False):
                    log.debug("blocked udp packet from %s to %s",packet.next.srcip,packet.next.dstip)
                    drop()
                    return
            if packet.find('icmp') is not None:  # icmp packets dropped
                if self.firewall.get(("icmp",packet.next.srcip,packet.next.dstip),False):
                    log.debug("blocked icmp packet from %s to %s",packet.next.srcip,packet.next.dstip)
                    drop()
                    return

            # tcp ports
            z = packet.find('tcp')
            if z:
                if z.srcport in  self.blocked_ports or z.dstport in self.blocked_ports:
                    log.debug("blocked TCP %s <-> %s",z.srcport,z.dstport)
                    drop()
                    return

        if not self.transparent: # 2
            if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
                drop() # 2a
                return
        if packet.dst.is_multicast:
            flood() # 3a
        else:
            if packet.dst not in self.macToPort: # 4
                flood("Port for %s unknown -- flooding" % (packet.dst,)) # 4a
            else:
                port = self.macToPort[packet.dst]
                if port == event.port: # 5
                # 5a
                    log.warning("Same port for packet from %s -> %s on %s.%s.  Drop."
                        % (packet.src, packet.dst, dpid_to_str(event.dpid), port))
                    drop(10)
                    return
                # 6
                log.debug("installing flow for %s.%i -> %s.%i" %
                        (packet.src, event.port, packet.dst, port))
                msg = of.ofp_flow_mod()
                msg.match = of.ofp_match.from_packet(packet, event.port)
                msg.idle_timeout = 10
                msg.hard_timeout = 30
                msg.actions.append(of.ofp_action_output(port = port))
                msg.data = event.ofp # 6a
                self.connection.send(msg)


class l2_learning (object):
    def __init__ (self, transparent, blocked_protocols, blocked_ports = None):
        core.openflow.addListeners(self)
        self.transparent = transparent
        self.blocked_protocols = blocked_protocols
        self.blocked_ports = blocked_ports

    def _handle_ConnectionUp (self, event):
        log.debug("Connection %s" % (event.connection,))
        LearningSwitch(event.connection, self.transparent,self.blocked_protocols,self.blocked_ports)


def launch (transparent=False, hold_down=_flood_delay, blocked_protocols = None, blocked_ports = None):
    try:
        global _flood_delay
        _flood_delay = int(str(hold_down), 10)
        assert _flood_delay >= 0
    except:
        raise RuntimeError("Expected hold-down to be a number")

    # if ignore:
    #     ignore = ignore.replace(',', ' ').split()
    #     ignore = set(str_to_dpid(dpid) for dpid in ignore)

    if blocked_protocols:
        blocked_protocols = list(blocked_protocols)

    if blocked_ports:
        blocked_ports = blocked_ports.split(",")
        blocked_ports = [int(x) for x in blocked_ports]

    core.registerNew(l2_learning, str_to_bool(transparent), blocked_protocols, blocked_ports)
