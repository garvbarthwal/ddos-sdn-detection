
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp
from ryu.lib import hub

import numpy as np
import time
import joblib
import logging

class RealTimeDDoSDetector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RealTimeDDoSDetector, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.flow_stats = {}
        self.blocked_ips = set()
        self.logger.setLevel(logging.INFO)
        self.model = joblib.load("model.joblib")
        self.monitor_thread = hub.spawn(self.monitor)

    def monitor(self):
        while True:
            current_time = time.time()
            for key, flow in list(self.flow_stats.items()):
                if current_time - flow['last_seen'] > 1:
                    features = self.extract_features(flow)
                    sample = np.array(features).reshape(1, -1)
                    prediction = self.model.predict(sample)[0]
                    src_ip = key[0]
                    if prediction == 1 and src_ip not in self.blocked_ips:
                        self.blocked_ips.add(src_ip)
                        self.logger.info(f"[ALERT] DDoS Detected - IP: {src_ip}, Protocol: {flow['protocol']}, Time: {time.ctime()}")
                    del self.flow_stats[key]
            hub.sleep(5)

    def extract_features(self, flow):
        duration = flow['last_seen'] - flow['first_seen']
        duration = duration if duration > 0 else 1e-6
        total_fwd = flow['fwd_packets']
        total_bwd = flow['bwd_packets']
        total_fwd_bytes = sum(flow['fwd_pkt_lengths'])
        total_bwd_bytes = sum(flow['bwd_pkt_lengths'])
        all_lengths = flow['fwd_pkt_lengths'] + flow['bwd_pkt_lengths']
        features = [
            flow['protocol'],
            duration,
            total_fwd,
            total_bwd,
            total_fwd_bytes,
            total_bwd_bytes,
            max(flow['fwd_pkt_lengths'], default=0),
            min(flow['fwd_pkt_lengths'], default=0),
            np.mean(flow['fwd_pkt_lengths']) if flow['fwd_pkt_lengths'] else 0,
            np.std(flow['fwd_pkt_lengths']) if flow['fwd_pkt_lengths'] else 0,
            max(flow['bwd_pkt_lengths'], default=0),
            min(flow['bwd_pkt_lengths'], default=0),
            np.mean(flow['bwd_pkt_lengths']) if flow['bwd_pkt_lengths'] else 0,
            np.std(flow['bwd_pkt_lengths']) if flow['bwd_pkt_lengths'] else 0,
            (total_fwd_bytes + total_bwd_bytes) / duration,
            (total_fwd + total_bwd) / duration,
            flow['fwd_psh_flags'],
            flow['bwd_psh_flags'],
            flow['fwd_urg_flags'],
            flow['bwd_urg_flags'],
            flow['fwd_header_total_len'],
            flow['bwd_header_total_len'],
            total_fwd / duration,
            total_bwd / duration,
            min(all_lengths, default=0),
            max(all_lengths, default=0),
            np.mean(all_lengths) if all_lengths else 0,
            np.std(all_lengths) if all_lengths else 0,
            np.var(all_lengths) if all_lengths else 0,
            flow['fin_flag_count'],
            flow['syn_flag_count'],
            flow['rst_flag_count'],
            flow['psh_flag_count'],
            flow['ack_flag_count'],
            flow['urg_flag_count'],
            flow['cwe_flag_count'],
            flow['ece_flag_count'],
            total_bwd / total_fwd if total_fwd > 0 else 0,
            np.mean(all_lengths) if all_lengths else 0,
            np.mean(flow['fwd_pkt_lengths']) if flow['fwd_pkt_lengths'] else 0,
            np.mean(flow['bwd_pkt_lengths']) if flow['bwd_pkt_lengths'] else 0,
            flow['subflow_fwd_packets'],
            flow['subflow_fwd_bytes'],
            flow['subflow_bwd_packets'],
            flow['subflow_bwd_bytes'],
            flow['init_win_bytes_fwd'],
            flow['init_win_bytes_bwd'],
            flow['act_data_pkt_fwd'],
            flow['min_seg_size_fwd']
        ]
        return features

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype != 0x0800:
            return
        ip = pkt.get_protocol(ipv4.ipv4)
        if ip is None or ip.src in self.blocked_ips:
            return
        proto = ip.proto
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        key = (ip.src, ip.dst, proto)
        now = time.time()
        if key not in self.flow_stats:
            self.flow_stats[key] = {
                'first_seen': now,
                'last_seen': now,
                'protocol': proto,
                'fwd_packets': 0,
                'bwd_packets': 0,
                'fwd_pkt_lengths': [],
                'bwd_pkt_lengths': [],
                'fwd_psh_flags': 0,
                'bwd_psh_flags': 0,
                'fwd_urg_flags': 0,
                'bwd_urg_flags': 0,
                'fwd_header_total_len': 0,
                'bwd_header_total_len': 0,
                'fin_flag_count': 0,
                'syn_flag_count': 0,
                'rst_flag_count': 0,
                'psh_flag_count': 0,
                'ack_flag_count': 0,
                'urg_flag_count': 0,
                'cwe_flag_count': 0,
                'ece_flag_count': 0,
                'subflow_fwd_packets': 0,
                'subflow_fwd_bytes': 0,
                'subflow_bwd_packets': 0,
                'subflow_bwd_bytes': 0,
                'init_win_bytes_fwd': tcp_pkt.window if tcp_pkt else 0,
                'init_win_bytes_bwd': 0,
                'act_data_pkt_fwd': 0,
                'min_seg_size_fwd': tcp_pkt.offset if tcp_pkt else 0
            }

        flow = self.flow_stats[key]
        flow['last_seen'] = now
        length = len(msg.data)
        if (in_port % 2) == 0:  # heuristic: even ports -> fwd
            flow['fwd_packets'] += 1
            flow['fwd_pkt_lengths'].append(length)
            flow['subflow_fwd_packets'] += 1
            flow['subflow_fwd_bytes'] += length
            flow['act_data_pkt_fwd'] += 1
            if tcp_pkt:
                flow['fwd_psh_flags'] += int(tcp_pkt.bits & 0x08 != 0)
                flow['fwd_urg_flags'] += int(tcp_pkt.bits & 0x20 != 0)
                flow['fwd_header_total_len'] += tcp_pkt.offset * 4
                flow['fin_flag_count'] += int(tcp_pkt.bits & 0x01 != 0)
                flow['syn_flag_count'] += int(tcp_pkt.bits & 0x02 != 0)
                flow['rst_flag_count'] += int(tcp_pkt.bits & 0x04 != 0)
                flow['psh_flag_count'] += int(tcp_pkt.bits & 0x08 != 0)
                flow['ack_flag_count'] += int(tcp_pkt.bits & 0x10 != 0)
                flow['urg_flag_count'] += int(tcp_pkt.bits & 0x20 != 0)
                flow['cwe_flag_count'] += int(tcp_pkt.bits & 0x40 != 0)
                flow['ece_flag_count'] += int(tcp_pkt.bits & 0x80 != 0)
        else:
            flow['bwd_packets'] += 1
            flow['bwd_pkt_lengths'].append(length)
            flow['subflow_bwd_packets'] += 1
            flow['subflow_bwd_bytes'] += length
            if tcp_pkt:
                flow['bwd_psh_flags'] += int(tcp_pkt.bits & 0x08 != 0)
                flow['bwd_urg_flags'] += int(tcp_pkt.bits & 0x20 != 0)
                flow['bwd_header_total_len'] += tcp_pkt.offset * 4
