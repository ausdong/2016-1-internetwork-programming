# -*- coding: utf-8 -*-
######################################################
# ECE4110 Spring 2016
# LoadBalancer.py
# Your Name: Austin Dong
# Date: 4/20/2016
######################################################
"""
An OpenFlow 3.0 LoadBalancer
"""


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, tcp # added ipv4, tcp

import logging
import struct
from ryu.controller import mac_to_port
from ryu.lib.mac import haddr_to_bin

############## Add your Global constants here #############
virtual_ip = '10.0.0.5'
virtual_mac = '00:00:00:00:00:05'
server = {}
server[0] = {'ip':'10.0.0.2', 'mac':'00:00:00:00:00:02', 'outport': 2}
server[1] = {'ip':'10.0.0.3', 'mac':'00:00:00:00:00:03', 'outport': 3}
server[2] = {'ip':'10.0.0.4', 'mac':'00:00:00:00:00:04', 'outport': 4}
total_servers = len(server)
server_index = 1 

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
      
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        ########################################################################
        #Add your code here to:
        global server_index
        #On a packet_in destined for virtual_ip coming from client “X” and TCP port 80
        http_match = parser.OFPMatch(in_port=1, eth_type=0x0800, eth_src = '00:00:00:00:00:01', eth_dst = virtual_mac, ip_proto=6, ipv4_src='10.0.0.1', ipv4_dst=virtual_ip, tcp_dst = 80)
        
        #Pick server “Y” using a round-robin algorithm
        index = server_index % total_servers
        server_index += 1
        selected_server_ip = server[index]['ip']
        selected_server_mac = server[index]['mac']
        selected_server_outport = server[index]['outport']
        #Insert flow rule to match on that packet:        
        #    Actions: 
        #    1) Rewrite dst_mac, dst_ip of packet to that of “Y”
        #    2) Forward to output port connected to “Y”
        http_actions = [parser.OFPActionSetField(eth_dst=selected_server_mac), parser.OFPActionSetField(ipv4_dst=selected_server_ip), parser.OFPActionOutput(selected_server_outport)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, http_actions)]
        mod = parser.OFPFlowMod(datapath=datapath, match=http_match, idle_timeout=10, instructions=inst)
        datapath.send_msg(mod)
        #Proactively insert reverse flow:
        #Match: SRC (IP, MAC, TCP_Port 80)from Y, Dst = X,
        rev_match = parser.OFPMatch(in_port=selected_server_outport, eth_type=0x0800, ip_proto=6, ipv4_src = selected_server_ip, ipv4_dst='10.0.0.1', eth_src = selected_server_mac, eth_dst='00:00:00:00:00:01', tcp_src = 80)
        #    Action: Rewrite src_mac, src_ip to that of virtual_ip, 
        #            Forward to output port connected to “X”
        rev_actions = [parser.OFPActionSetField(eth_src=virtual_mac), parser.OFPActionSetField(ipv4_src=virtual_ip), parser.OFPActionOutput(1)]
        self.add_flow(datapath, 2, rev_match, rev_actions)
        #All subsequent packets of the request will directly be sent to the chosen server and not be seen by the controller.
        ###########################################################################
        
        # if not packet taken care of above with a higher priority rule
        # add a lower priority rule to learn a mac address to avoid FLOOD next time.
        # creating a table for mapping ports to mac for a datapath
        
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
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
