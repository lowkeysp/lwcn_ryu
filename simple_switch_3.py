# encoding=utf-8
# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


#该版本比较上一个版本，在packet_in那里进行了处理，要手动输入流表（端口1和端口2之间的流表），然后切换流表后
#改变流表为（端口1和端口3）


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import hub
import eventlet
import eventlet.greenthread
import time


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.my_thread=hub.spawn(self._listen)
        self.datapaths={}
        self.port_to_mac = {}
        self.loadbalance= {}
        self.BASESTATION = 0



    def handle(self,new_sock, address):
        while True:
            c = new_sock.recv(1024)

            if not c:
                break
            number = int(c)

            self.loadbalance.setdefault(address[0], [])
            self.loadbalance[address[0]].append(number)
            print("****************")
            print(self.loadbalance)
            #print(self.port_to_mac)

    def decision(self):
        while True:
            address_tuple = self.loadbalance.keys()
            addr1_load = self.loadbalance[address_tuple[0]]
            addr2_load = self.loadbalance[address_tuple[1]]
            if (len(addr1_load) >= 10 and len(addr2_load) >= 10):
                sum1 = 0
                sum2 = 0
                addr1_load.sort()
                addr2_load.sort()
                addr1_load.pop(9)
                addr2_load.pop(9)
                addr1_load.pop(0)
                addr2_load.pop(0)
                for i in range(0, 8):

                    sum1 = sum1 + addr1_load.pop(0)
                    sum2 = sum2 + addr2_load.pop(0)
                if sum2 < sum1:
                    print("zhixingqiehuan")
                    self._modified_flow()
            eventlet.greenthread.sleep(0.2)

    def _listen(self):
        server = eventlet.listen(('0.0.0.0',6000))
        pool = eventlet.GreenPool()
        flag = True

        while True:
            try:
                new_socket,address = server.accept()
                print("accepted",address)
                pool.spawn(self.handle, new_socket, address)
                self.BASESTATION += 1
                if (self.BASESTATION == 2 and flag):
                    time.sleep(5)
                    pool.spawn(self.decision)
                    flag = False
            except(SystemExit,KeyboardInterrupt):
                break;



    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        if datapath.id not in self.datapaths:
            self.datapaths[datapath.id] = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)



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

    def _modified_flow(self):
        datapath = self.datapaths.values()[0]

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(in_port=1,eth_dst=self.port_to_mac[datapath.id][2])
        #actions = [parser.OFPActionOutput(3)]
        self.delete_flow(datapath,1,match)

        match = parser.OFPMatch(in_port=2, eth_dst=self.port_to_mac[datapath.id][1])
        self.delete_flow(datapath,1,match)

        match = parser.OFPMatch(in_port=1,eth_dst=self.port_to_mac[datapath.id][3])
        actions=[parser.OFPActionOutput(3)]
        self.add_flow(datapath,1,match,actions)

        match = parser.OFPMatch(in_port=3,eth_dst=self.port_to_mac[datapath.id][1])
        actions=[parser.OFPActionOutput(1)]
        self.add_flow(datapath,1,match,actions)





    def delete_flow(self,datapath,priority,match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        #inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                            # actions)]

        mod = parser.OFPFlowMod(datapath=datapath,command=ofproto.OFPFC_DELETE,priority=priority,
                                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                                match=match)

        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
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

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.port_to_mac.setdefault(dpid, {})


        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        self.port_to_mac[dpid][in_port] = src


        if dst not in self.mac_to_port[dpid]:
            out_port = ofproto.OFPP_FLOOD
            actions = [parser.OFPActionOutput(out_port)]
            data = None

            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)




        """
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
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

        """