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


#该版本是控制器自己监控端口流量，如果端口2的流量比端口3的大，而且端口2的流量超过一定的阈值，则进行切换
#和上一个版本同样的是需要自己建立一个端口1到端口2的流表


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
from operator import attrgetter


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths={}
        self.port_to_mac = {}
        self.BASESTATION = 0
        self.monitor_thread = hub.spawn(self._monitor)
        self.bytes={}
        self.total_bytes = {}
        self.flag = True
        self.pool = eventlet.GreenPool()

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)


    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body

        for stat in sorted(body, key=attrgetter('port_no')):
            if(not(stat.port_no == 2 or stat.port_no == 3)):

                continue

            self.bytes.setdefault(stat.port_no,[])
            total_bytes = self.total_bytes.setdefault(stat.port_no,0)
            self.bytes[stat.port_no].append(float("%.2f" %( (stat.rx_bytes + stat.tx_bytes-total_bytes)/(1000000*10.0/8)))  )
            self.total_bytes[stat.port_no] = stat.rx_bytes + stat.tx_bytes
            print("#############################")
            print(stat.rx_bytes)
            print(stat.tx_bytes)
            print(total_bytes)


        print(self.bytes)
        if self.flag:
            self.pool.spawn(self._decision)
            self.flag = False


    def _decision(self):
        while True:
            port_no_tuple = self.bytes.keys()

            port2_bytes = self.bytes[port_no_tuple[0]]
            port3_bytes = self.bytes[port_no_tuple[1]]
            if(len(port2_bytes) >=10 and len(port3_bytes) >=10):

                sum2 = 0
                sum3 = 0
                port2_bytes.sort()
                port3_bytes.sort()
                port2_bytes.pop(9)
                port3_bytes.pop(9)
                port2_bytes.pop(0)
                port3_bytes.pop(0)
                for i in range(0, 8):

                    sum2 = sum2 + port2_bytes.pop(0)
                    sum3 = sum3 + port3_bytes.pop(0)
                if sum2 > sum3 and sum2/8 > 10.0:
                    print("zhixingqiehuan")
                    self._modified_flow()
            eventlet.greenthread.sleep(0.2)





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

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

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


