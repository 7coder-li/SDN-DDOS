from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4
from ryu.lib import hub
import requests
import time

class DDoSMonitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DDoSMonitor, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.blocked_ips = set()
        
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info(f"Register datapath: {datapath.id}")
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info(f"Unregister datapath: {datapath.id}")
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(3)

    def _request_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    def block_attacker(self, datapath, attacker_ip):
        if attacker_ip in self.blocked_ips:
            return
            
        self.logger.info(f"[DEFENSE] Blocking malicious IP: {attacker_ip}")
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=attacker_ip)
        inst = [] 
        mod = parser.OFPFlowMod(datapath=datapath, priority=100, match=match, instructions=inst)
        datapath.send_msg(mod)
        self.blocked_ips.add(attacker_ip)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        flows = {}

        for stat in body:
            if stat.match.get('eth_type') == 0x0800:
                src = stat.match.get('ipv4_src')
                dst = stat.match.get('ipv4_dst')
                proto = stat.match.get('ip_proto')
                if src and dst and proto:
                    flows[(src, dst, proto)] = stat

        for (src, dst, proto), fwd_stat in flows.items():
            if src in self.blocked_ips:
                continue

            fwd_pkts = fwd_stat.packet_count
            fwd_bytes = fwd_stat.byte_count
            duration = fwd_stat.duration_sec + (fwd_stat.duration_nsec / 1e9)

            bwd_stat = flows.get((dst, src, proto))
            bwd_pkts = bwd_stat.packet_count if bwd_stat else 0
            bwd_bytes = bwd_stat.byte_count if bwd_stat else 0
            bwd_duration = (bwd_stat.duration_sec + (bwd_stat.duration_nsec / 1e9)) if bwd_stat else 0

            flow_duration = max(duration, bwd_duration)
            if flow_duration <= 0: flow_duration = 0.0001

            tot_pkts = fwd_pkts + bwd_pkts
            tot_bytes = fwd_bytes + bwd_bytes
            avg_pkt_size = tot_bytes / tot_pkts if tot_pkts > 0 else 0

            if fwd_pkts > 10:
                features = {
                    'Protocol': proto,
                    'Flow Duration': flow_duration,
                    'Total Fwd Packets': fwd_pkts,
                    'Total Length of Fwd Packets': fwd_bytes,
                    'Total Backward Packets': bwd_pkts,
                    'Total Length of Bwd Packets': bwd_bytes,
                    'Average Packet Size': avg_pkt_size
                }
                
                try:
                    resp = requests.post('http://127.0.0.1:5000/predict', json=features, timeout=1)
                    if resp.status_code == 200:
                        result = resp.json()
                        if result.get('is_attack'):
                            self.logger.warning(f"[ALERT] Attack Detected! Src: {src} -> Dst: {dst} (Prob: {result.get('attack_probability'):.2%})")
                            self.block_attacker(ev.msg.datapath, src)
                except requests.exceptions.RequestException:
                    pass

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP: return
        dst, src = eth.dst, eth.src
        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        out_port = self.mac_to_port[dpid][dst] if dst in self.mac_to_port[dpid] else ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip_pkt = pkt.get_protocol(ipv4.ipv4)
                match = parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_IP,
                                        ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst, 
                                        ip_proto=ip_pkt.proto)
                priority = 10
            elif eth.ethertype == ether_types.ETH_TYPE_ARP:
                match = parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_ARP, eth_dst=dst, eth_src=src)
                priority = 5
            else:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                priority = 1
                
            self.add_flow(datapath, priority, match, actions, msg.buffer_id if msg.buffer_id != ofproto.OFP_NO_BUFFER else None)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER: return

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
