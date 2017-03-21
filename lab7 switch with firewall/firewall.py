######################################################
# ECE4110 Spring 2016
# firewall.py
# Your Name: Austin Dong
# Date: March 30, 2016-March 31, 2016
# modified lines: 91-116, 131-149, 167-174
######################################################
"""
An OpenFlow 3.0 firewall
"""


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

import logging
import struct
from ryu.controller import mac_to_port
from ryu.lib.mac import haddr_to_bin
#*****added following line
from ryu.lib.packet import arp, ipv4, icmp, tcp, udp




class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    # this function adds a default rule with low priority 0
    # to send any packets that do not have a table entry
    #to the controller
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
    
    #this function sends the rule from the controller to the switch
    #for entry in the switch table
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
    
    #This function handles a packet in event in the controller
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
             
        datapath = msg.datapath
        
        ofproto = datapath.ofproto
        
        parser = datapath.ofproto_parser
        
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        dst = eth.dst
        src = eth.src
#*********************** added this section for troubleshooting and getting additional values*
        ipv4proto = 0
        tcp_dstport = 0
        tcp_srcport = 0
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_icmp= pkt.get_protocol(icmp.icmp)
        pkt_arp = pkt.get_protocol(arp.arp)
        pkt_tcp= pkt.get_protocol(tcp.tcp)
        pkt_udp= pkt.get_protocol(udp.udp)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        #if pkt_arp!= None:
         #   print "ARP"
        #if pkt_icmp != None:
         #   print "ICMP"  
        if pkt_ipv4 != None:
         #   print "IPv4"
            ipv4proto = pkt_ipv4.proto # get IPv4 protocol number to know ICMP or TCP
        if pkt_tcp != None:
         #   print "TCP"
            tcp_dstport = pkt_tcp.dst_port # get TCP destination port
            tcp_srcport = pkt_tcp.src_port # get TCP source port
         #   print tcp_srcport
         #   print tcp_dstport
        ethertype = pkt_ethernet.ethertype # get ethernet type to know ARP or IP
        #print ethertype
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
             
        ########################################################################
        #Add your code here to:
        #1) to create matches on TCP packets using parser.OFPMatch(fill in fields here to match on)
        #2) create actions using [parser.OFPActionOutput(port to send to goes in here)]
        #3) call self.add_flow(datapath, a priority value where larger value is higher priority, a match rule from your step one, an action from your step 2)
        
        ###########################################################################
		  
#****************added this section for new matches, actions, and add_flows*****************
        match = parser.OFPMatch(in_port=in_port, eth_type=ethertype, tcp_src=tcp_srcport, tcp_dst=tcp_dstport, eth_src=src, eth_dst=dst, ip_proto=ipv4proto) #TCP HTTP h1 to h2 match
        if match['eth_src']=='00:00:00:00:00:01' and match['eth_dst']=='00:00:00:00:00:02': # if h1 to h2
            if tcp_dstport == 80 or tcp_srcport == 22: # if h1 sending http or replying ssh
               #print("h1 to h2 MATCH")
               actions = [parser.OFPActionOutput(2)]  # action is output to port 2 (where h2 is)
               self.add_flow(datapath, 3, match, actions, msg.buffer_id) # add flow
               return #exit because we are done
        if match['eth_src']=='00:00:00:00:00:02' and match['eth_dst']=='00:00:00:00:00:01': # if h2 to h1
            if tcp_dstport == 22 or tcp_srcport == 80: # if h2 sending ssh or replying http
               #print("h2 to h1 MATCH")
               actions = [parser.OFPActionOutput(1)] # action is output to port 1
               self.add_flow(datapath, 3, match, actions, msg.buffer_id) # add flow
               return #exit because we are done
        if match['ip_proto']==6: #if packet is TCP
            #print("DROP MATCH")
            self.add_flow(datapath, 2, match, []) # apparently empty action means drop the packet
            return # exit
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
		  
        # if not packet taken care of above with a higher priority rule
        # add a lower priority rule to learn a mac address to avoid FLOOD next time.
        # creating a table for mapping ports to mac for a datapath
        #if pkt_arp == None and pkt_icmp == None: #if not 
         #   return
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
#********************* modified this section to check if packet is random IPv6 or ARP or other (ICMP)*******
            if ethertype == 34525:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            elif pkt_arp != None:
                match = parser.OFPMatch(in_port=in_port, eth_type=ethertype, eth_dst=dst)
            else:
                match = parser.OFPMatch(in_port=in_port, eth_type=ethertype, eth_dst=dst, ip_proto=ipv4proto)
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
                
        # For ping, data = None                
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
 
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
                                  
        #Send the message to the switch                                                                  
        datapath.send_msg(out)
