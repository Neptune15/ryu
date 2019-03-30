from ryu.base import app_manager
from ryu.base.app_manager import lookup_service_brick
from ryu.ofproto import ofproto_v1_3
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.controller import ofp_event
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, arp
from ryu.lib import hub
from ryu.topology import event
from ryu.topology.api import get_host, get_link, get_switch
from ryu.topology.switches import LLDPPacket

import networkx as nx
import copy
import time


GET_TOPOLOGY_INTERVAL = 2
SEND_ECHO_REQUEST_INTERVAL = .05
GET_DELAY_INTERVAL = 2


class NetworkAwareness(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(NetworkAwareness, self).__init__(*args, **kwargs)

        self.switch_info = {}  # dpid: datapath
        self.link_info = {}  # (s1, s2): s1.port
        self.port_info = {}  # dpid: (ports linked hosts)
        self.topo_map = nx.Graph()
        self.topo_thread = hub.spawn(self._get_topology)

        # delay detect
        self.switches = lookup_service_brick('switches')  # get the class in running
        self.echo_delay = {}
        self.lldp_delay = {}
        self.link_delay = {}
        self.topo_thread = hub.spawn(self._get_delay)

    def add_flow(self, datapath, priority, match, actions):
        dp = datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=priority, match=match, instructions=inst)
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        dp = ev.datapath
        dpid = dp.id

        if ev.state == MAIN_DISPATCHER:
            self.switch_info[dpid] = dp

        if ev.state == DEAD_DISPATCHER:
            del self.switch_info[dpid]

    def _get_topology(self):
        _hosts, _switches, _links = None, None, None
        while True:
            hosts = get_host(self)
            switches = get_switch(self)
            links = get_link(self)

            # update topo_map when topology change
            if [str(x) for x in hosts] == _hosts and [str(x) for x in switches] == _switches and [str(x) for x in links] == _links:
                continue
            _hosts, _switches, _links = [str(x) for x in hosts], [str(x) for x in switches], [str(x) for x in links]

            for switch in switches:
                self.port_info.setdefault(switch.dp.id, set())
                # record all ports
                for port in switch.ports:
                    self.port_info[switch.dp.id].add(port.port_no)

            for host in hosts:
                # take one ipv4 address as host id
                if host.ipv4:
                    self.link_info[(host.port.dpid, host.ipv4[0])] = host.port.port_no
                    self.topo_map.add_edge(host.ipv4[0], host.port.dpid, hop=1, is_host=True)
            for link in links:
                # delete ports linked switches
                self.port_info[link.src.dpid].discard(link.src.port_no)
                self.port_info[link.dst.dpid].discard(link.dst.port_no)

                # s1 -> s2: s1.port, s2 -> s1: s2.port
                self.link_info[(link.src.dpid, link.dst.dpid)] = link.src.port_no
                self.link_info[(link.dst.dpid, link.src.dpid)] = link.dst.port_no
                self.topo_map.add_edge(link.src.dpid, link.dst.dpid, hop=1, is_host=False)

            self.show_topo_map()
            hub.sleep(GET_TOPOLOGY_INTERVAL)

    def shortest_path(self, src, dst, weight='hop'):
        try:
            paths = list(nx.shortest_simple_paths(self.topo_map, src, dst, weight=weight))
            return paths[0]            
        except:
            self.logger.info('host not find/no path')

    def show_topo_map(self):
        self.logger.info('topo map:')
        self.logger.info('{:^10s}  ->  {:^10s}'.format('node', 'node'))
        for src, dst in self.topo_map.edges:
            self.logger.info('{:^10s}      {:^10s}'.format(str(src), str(dst)))
        self.logger.info('\n')

    # for delay detect
    def _get_delay(self):
        while True:
            self.send_echo_request()
            self.calc_delay()

            hub.sleep(GET_DELAY_INTERVAL)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_hander(self, ev):
        msg = ev.msg
        dpid = msg.datapath.id
        try:
            src_dpid, src_port_no = LLDPPacket.lldp_parse(msg.data)

            if self.switches is None:
                self.switches = lookup_service_brick('switches')

            for port in self.switches.ports.keys():
                if src_dpid == port.dpid and src_port_no == port.port_no:
                    self.lldp_delay[(src_dpid, dpid)] = self.switches.ports[port].delay
        except:
            return

    def send_echo_request(self):
        for dp in self.switch_info.values():
            parser = dp.ofproto_parser
            echo_req = parser.OFPEchoRequest(dp, data='{:.10f}'.format(time.time()))
            dp.send_msg(echo_req)

            hub.sleep(SEND_ECHO_REQUEST_INTERVAL)

    @set_ev_cls(ofp_event.EventOFPEchoReply, MAIN_DISPATCHER)
    def echo_reply_handler(self, ev):
        try:
            self.echo_delay[ev.msg.datapath.id] = time.time() - eval(ev.msg.data)
        except:
            return

    def calc_delay(self):
        for src_dpid, dst_dpid in self.topo_map.edges:
            if self.topo_map[src_dpid][dst_dpid]['is_host']:
                delay = 0
            else:
                try:
                    lldp_from_delay = self.lldp_delay[(src_dpid, dst_dpid)]
                    lldp_to_delay = self.lldp_delay[(dst_dpid, src_dpid)]
                    echo_request_delay = self.echo_delay[src_dpid]
                    echo_reply_delay = self.echo_delay[dst_dpid]

                    delay = max((lldp_from_delay + lldp_to_delay - echo_request_delay - echo_reply_delay) / 2.0, 0)
                except:
                    delay = float('inf')
            self.topo_map.add_edge(src_dpid, dst_dpid, delay=delay * 1000)  # s -> ms
        self.show_delay_map()

    def show_delay_map(self):
        self.logger.info('delay map:')
        self.logger.info('{:^10s}  ->  {:^10s}      {:^10s}'.format('node', 'node', 'delay'))
        for src, dst in self.topo_map.edges:
            self.logger.info('{:^10s}      {:^10s}      {:^8.2f}ms'.format(str(src), str(dst),
                                                                           self.topo_map[src][dst]['delay']))
        self.logger.info('\n')
