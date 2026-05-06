"""
 Copyright (c) 2026 Computer Networks Group @ UPB

 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 """

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu import utils
from ryu.lib.packet import *


class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)

        # Here you can initialize the data structures you want to keep at the controller
        self.mac_port_map = {} #dictionary implementation of forwarding table to store mappings in the controller, the structure is dpid: {mac: port}
        

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Initial flow entry for matching misses
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    # Add a flow entry to the flow-table
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Construct flow_mod message and send it
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    # Handle the packet_in event
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        
        msg = ev.msg
        datapath = msg.datapath
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        buffer_id = msg.buffer_id
        dpid = datapath.id
        #annotating dpid from simple integer datatype to it's 64bit representation in string
        dpid = f"{dpid:016x}"

        #analyse the packet
        data_packet = packet.Packet(msg.data)
        ethernet_protocol = data_packet.get_protocols(ethernet.ethernet)[0]

        src_mac = ethernet_protocol.src
        dest_mac = ethernet_protocol.dst

        # print(f"The ethernet type is {ethernet_protocol.ethertype}, with source at {src_mac} and destination at {dest_mac}.")
        self.logger.info(f"Packet inbound -- source: {src_mac} destination: {dest_mac} in_port: {in_port} datapath_id: {dpid} ethertype: {ethernet_protocol.ethertype} buffer_id: {msg.buffer_id}")
        self.logger.info(f"Mac to Port Mapping: {self.mac_port_map}")

        #using setdefault to initialize the mac port mapping dictionary with dpid key if not exists already
        self.mac_port_map.setdefault(dpid, {})

        #Checking if the source mac address is in the mac to port mapping, if not adding it in the dict.
        if src_mac not in self.mac_port_map:
            self.mac_port_map[dpid][src_mac] = in_port
        
        #Logic for checking if mac address mapping exists or not
        if dest_mac in self.mac_port_map[dpid]:
            out_port = self.mac_port_map[dpid][dest_mac] 
            actions = [ofp_parser.OFPActionOutput(out_port)]    
            match = ofp_parser.OFPMatch(in_port=in_port, eth_dst=dest_mac, eth_src=src_mac)
            self.add_flow(datapath, 1, match, actions)       
        else:
            out_port = ofp.OFPP_FLOOD
            actions = [ofp_parser.OFPActionOutput(out_port)]    


        #discarding data if it's in switch's buffer. 
        if buffer_id != ofp.OFP_NO_BUFFER:
            data = None
        else:
            data = msg.data

        self.logger.info(f"Response Controller to Switch: datapath={datapath}, buffer_id={buffer_id}, in_port={in_port}, actions={actions}, data={data}, out_port={out_port}")

        #send the message
        datapath.send_msg(ofp_parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id, in_port=in_port, actions=actions, data=data))


        # if msg.reason == ofp.OFPR_NO_MATCH:
        #     reason = 'NO MATCH'
        # elif msg.reason == ofp.OFPR_ACTION:
        #     reason = 'ACTION'
        # elif msg.reason == ofp.OFPR_INVALID_TTL:
        #     reason = 'INVALID TTL'
        # else:
        #     reason = 'unknown'

        # self.logger.debug('OFPPacketIn received: '
        #                 'buffer_id=%x total_len=%d reason=%s '
        #                 'table_id=%d cookie=%d match=%s data=%s in_port=%s datapath_id=%s',
        #                 msg.buffer_id, msg.total_len, reason,
        #                 msg.table_id, msg.cookie, msg.match,
        #                 utils.hex_array(msg.data), msg.match['in_port'], datapath.id)
        # print(type(datapath.id))
        # # This is the datapath ID print(datapath.id)
        # print(vars(msg))
        # # print(msg.match._fields2)
        # print(msg.datapath_id)

        # Your controller implementation should start here