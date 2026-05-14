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
from ryu.lib.packet.in_proto import IPPROTO_ICMP
from ryu.lib.packet.icmp import ICMP_ECHO_REPLY
from ryu.lib.packet.ether_types import ETH_TYPE_IPV6, ETH_TYPE_ARP, ETH_TYPE_IP
from ryu.lib.mac import BROADCAST_STR, DONTCARE_STR


class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)

        # Here you can initialize the data structures you want to keep at the controller
        self.mac_port_map = {} #dictionary implementation of forwarding table to store mappings in the controller, the structure is dpid: {mac: port}
        
        # Router port MACs assumed by the controller
        self.port_to_own_mac = {
            1: "00:00:00:00:01:01",
            2: "00:00:00:00:01:02",
            3: "00:00:00:00:01:03"
        }
        # Router port (gateways) IP addresses assumed by the controller
        self.port_to_own_ip = {
        1: "10.0.1.1",
        2: "10.0.2.1",
        3: "192.168.1.1"
        }
        #self learning arp table
        self.arp_table = {} #just ip -> mac entries

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
        data_packet = packet.Packet(msg.data)
        ethernet_protocol = data_packet.get_protocols(ethernet.ethernet)[0]

        #getting rid of ipv6 packet noise
        if ethernet_protocol.ethertype == ETH_TYPE_IPV6:
            self.logger.info(f"Dropping IPV6 packet {ethernet_protocol}")
            return


        #differentiating approach between switch and router handling via dpid, s3 being the router
        if datapath.id in [1,2]:
            
            self.logger.info("*****************************")
            self.logger.info("SWITCH TRIGGERED!")
            self.logger.info(f"Switch Packet: {vars(msg)}")
            self.logger.info(f"DPID: {datapath.id}")
            self.logger.info("*****************************")
            #switch logic here
            
            src_mac = ethernet_protocol.src
            dest_mac = ethernet_protocol.dst

            # print(f"The ethernet type is {ethernet_protocol.ethertype}, with source at {src_mac} and destination at {dest_mac}.")
            self.logger.info(f"Packet inbound -- source: {src_mac} destination: {dest_mac} in_port: {in_port} datapath_id: {dpid} ethertype: {ethernet_protocol.ethertype} buffer_id: {msg.buffer_id}")
            self.logger.info(f"Mac to Port Mapping: {self.mac_port_map}")

            #using setdefault to initialize the mac port mapping dictionary with dpid key if not exists already
            self.mac_port_map.setdefault(dpid, {})

            #Checking if the source mac address is in the mac to port mapping, if not adding it in the dict.
            if src_mac not in self.mac_port_map[dpid]:
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

        
        elif datapath.id in [3]:
            self.logger.info("-----------------------------------")
            self.logger.info("ROUTER TRIGGERED!")
            self.logger.info(f"Router Packet: {vars(msg)}")
            self.logger.info(f"DPID: {datapath.id}")
            self.logger.info(f"Protocols: {data_packet.protocols}")
            # self.logger.info(f"Protocols type: {any(isinstance(x, ipv6.ipv6) for x in data_packet.protocols)}")
            # self.logger.info(f"Protocols type: {ipv6.ipv6 in [type(x) for x in data_packet.protocols]}")
            
            self.logger.info("-----------------------------------")
            self.logger.info(f"ARP Table: {self.arp_table}")

            
            # arp.arp in [type(x) for x in data_packet.protocols] - logic for finding if arp in request
            if arp.arp in [type(x) for x in data_packet.protocols]:
                arp_proto = data_packet.get_protocols(arp.arp)[0]
                # self.logger.info(f"APR_PROTO: {data_packet.get_protocols(arp.arp)}")
                dst_ip = arp_proto.dst_ip
                dst_mac = arp_proto.dst_mac #not relevant in any logic yet
                opcode = arp_proto.opcode #should be 2 when replying
                src_ip = arp_proto.src_ip
                src_mac = arp_proto.src_mac


                #self learning arp table -- removed the if condition because ip assignments can change with time.
                self.arp_table[src_ip] = src_mac

                if dst_ip in self.port_to_own_ip.values() and opcode == arp.ARP_REQUEST:
                    port = next(k for k,v in self.port_to_own_ip.items() if v == dst_ip) 
                    src_mac_response = self.port_to_own_mac[port]
                    # self.logger.info(f"Sending response mac: {dst_mac_response} while src_ip is {src_ip}")
                    #draft mac response here
                    response_packet = packet.Packet()

                    eth_proto_response = ethernet.ethernet(dst=src_mac,src=src_mac_response, ethertype=ETH_TYPE_ARP)
                    arp_proto_response = arp.arp(opcode=arp.ARP_REPLY, src_mac=src_mac_response,
                                                 src_ip=dst_ip, dst_mac=src_mac, dst_ip=src_ip)
                    response_packet.add_protocol(eth_proto_response)
                    response_packet.add_protocol(arp_proto_response)
                    
                    #conversion to binary
                    response_packet.serialize()

                    #define actions
                    out_port = in_port
                    actions = [ofp_parser.OFPActionOutput(out_port)]
                    #send final response
                    self.logger.info(f"Sending ARP response... with these actions: {actions}")
                    datapath.send_msg(ofp_parser.OFPPacketOut(datapath=datapath, buffer_id=ofp.OFP_NO_BUFFER, in_port=ofp.OFPP_CONTROLLER, actions=actions, data=response_packet.data))


            elif ipv4.ipv4 in [type(x) for x in data_packet.protocols]:
                self.logger.info("IPV4 Packet received.. Reencapsulation for IPV4")
                ipv4_proto = data_packet.get_protocols(ipv4.ipv4)[0]
                dst_ip = ipv4_proto.dst
                dst_ip_prefix = ".".join(dst_ip.split(".")[:3]) #this because every subnet is /24 in the task 
                src_ip = ipv4_proto.src
                src_ip_prefix = ".".join(ipv4_proto.src.split(".")[:3])
                blocked_icmp_prefix = [".".join(self.port_to_own_ip[3].split(".")[:3])]
                server_subnet_prefix = [".".join(self.port_to_own_ip[2].split(".")[:3])]

                #firewall implementation    
                if (dst_ip_prefix in blocked_icmp_prefix) != (src_ip_prefix in blocked_icmp_prefix):
                    self.logger.info(f"================= Handling Suspicious Packet =================")
                    self.logger.info(f"{src_ip_prefix} = SRC PREFIX & {dst_ip_prefix} = DST PREFIX")
                    #send flow to drop packet
                    if ipv4_proto.proto == IPPROTO_ICMP:
                        self.logger.info(f"Dropping illegal ICMP")
                        match = ofp_parser.OFPMatch(eth_type=ETH_TYPE_IP, ipv4_dst=dst_ip, ipv4_src=ipv4_proto.src, ip_proto=IPPROTO_ICMP)
                        actions = [] #drop
                        self.add_flow(datapath, 101, match=match, actions=actions)
                        return
                    
                    elif (dst_ip_prefix in server_subnet_prefix) or (src_ip_prefix in server_subnet_prefix):
                        self.logger.info(f"Dropping Illegal Server Packet")
                        match = ofp_parser.OFPMatch(eth_type=ETH_TYPE_IP, ipv4_dst=dst_ip, ipv4_src=ipv4_proto.src)
                        actions = [] #drop
                        self.add_flow(datapath, 100, match=match, actions=actions) #giving firewall higher priority
                        return
                
                #stopping other gateway access
                if src_ip_prefix != dst_ip_prefix:
                    if dst_ip in self.port_to_own_ip.values():
                        self.logger.info(f"Illegal access to unauthorized gateway")
                        match = ofp_parser.OFPMatch(eth_type=ETH_TYPE_IP, ipv4_dst=dst_ip, ipv4_src=ipv4_proto.src)
                        actions = [] #drop
                        self.add_flow(datapath, 99, match=match, actions=actions) #giving firewall higher priority
                        return
                


                for router_ip in self.port_to_own_ip.values():
                    router_prefix = ".".join(router_ip.split(".")[:3])
                    if dst_ip_prefix == router_prefix:
                        port = next(k for k,v in self.port_to_own_ip.items() if v == router_ip)
                        reenc_src_mac = self.port_to_own_mac[port]
                        out_port = next(k for k,v in self.port_to_own_ip.items() if v == router_ip)

                        #three conditions here, one where dst_ip is one of router's ips, one where the ip to mac is in the arp table, another when it's not
                        if dst_ip == router_ip and ipv4_proto.proto == IPPROTO_ICMP:
                            #icmp response to icmp req here
                            icmp_proto = data_packet.get_protocols(icmp.icmp)[0]
                            icmp_packet = packet.Packet()
                            icmp_resp_eth = ethernet.ethernet(dst=ethernet_protocol.src, src=reenc_src_mac, ethertype=ETH_TYPE_IP)
                            icmp_resp_ipv4 = ipv4.ipv4(dst=src_ip, src=router_ip, proto=IPPROTO_ICMP)
                            icmp_resp_header = icmp.icmp(type_=ICMP_ECHO_REPLY, data=icmp_proto.data)
                            icmp_packet.add_protocol(icmp_resp_eth)
                            icmp_packet.add_protocol(icmp_resp_ipv4)
                            icmp_packet.add_protocol(icmp_resp_header)
                            icmp_packet.serialize()
                            actions = [ofp_parser.OFPActionOutput(out_port)]
                            #send final response
                            self.logger.info(f"Sending ICMP response for {src_ip} from {router_ip}... with these actions: {actions}")
                            datapath.send_msg(ofp_parser.OFPPacketOut(datapath=datapath, buffer_id=ofp.OFP_NO_BUFFER, in_port=ofp.OFPP_CONTROLLER, actions=actions, data=icmp_packet.data))
                            return


                        elif dst_ip in self.arp_table:
                            #set destination mac here
                            reenc_dst_mac = self.arp_table[dst_ip]
                            actions = []
                            actions.append(ofp_parser.OFPActionSetField(eth_src=reenc_src_mac))
                            actions.append(ofp_parser.OFPActionSetField(eth_dst=reenc_dst_mac))
                            actions.append(ofp_parser.OFPActionOutput(port))

                            if buffer_id != ofp.OFP_NO_BUFFER:
                                data = None
                            else:
                                data = msg.data

                            self.logger.info(f"Adding flow rule to the router...")
                            match = ofp_parser.OFPMatch(eth_type=ETH_TYPE_IP, ipv4_dst=dst_ip, ipv4_src=ipv4_proto.src)
                            self.add_flow(datapath, 1, match=match, actions=actions)

                            self.logger.info(f"FORWARDING, router_prefix = {router_prefix}, dst_prefix = {dst_ip_prefix} : Forwarding packet...")
                            datapath.send_msg(ofp_parser.OFPPacketOut(datapath=datapath, in_port=in_port, buffer_id=msg.buffer_id, actions=actions, data=data))
                            break

                        else:
                            #flood and drop packet
                            self.logger.info("FLOOD HERE")
                            arp_req_packet = packet.Packet()
                            arp_req_eth = ethernet.ethernet(dst=BROADCAST_STR,src=reenc_src_mac, ethertype=ETH_TYPE_ARP)
                            arp_req_proto = arp.arp(opcode=arp.ARP_REQUEST, src_mac=reenc_src_mac,
                                                        src_ip=router_ip, dst_mac=DONTCARE_STR, dst_ip=dst_ip)
                            arp_req_packet.add_protocol(arp_req_eth)
                            arp_req_packet.add_protocol(arp_req_proto)        
                            arp_req_packet.serialize()
                            #define actions
                            actions = [ofp_parser.OFPActionOutput(out_port)]
                            #send final response
                            self.logger.info(f"Sending ARP request for {dst_ip} from {router_ip}... with these actions: {actions}")
                            datapath.send_msg(ofp_parser.OFPPacketOut(datapath=datapath, buffer_id=ofp.OFP_NO_BUFFER, in_port=ofp.OFPP_CONTROLLER, actions=actions, data=arp_req_packet.data))
                            return
                        
                          

                    else:
                        pass
                        # self.logger.info(f"UNKNOWN SUBNET, router_prefix = {router_prefix}, dst_prefix = {dst_ip_prefix} : Dropping packet...")
                        # self.logger.info(f"Router's prefixes are: {self.port_to_own_ip.values()}")
                        # return
                
                    
                return
                # elif dst_ip 
                    #gateway logic here

            
            #because all the subnets are /24, writing a simple prefix extraction


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