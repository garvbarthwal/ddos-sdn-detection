from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, arp
from ryu.lib import hub
import pandas as pd
import time
import numpy as np
import logging
from tensorflow.keras.models import load_model
import joblib

TCP_FLAG_FIN = 0x01
TCP_FLAG_SYN = 0x02
TCP_FLAG_RST = 0x04
TCP_FLAG_PSH = 0x08
TCP_FLAG_ACK = 0x10
TCP_FLAG_URG = 0x20
TCP_FLAG_ECE = 0x40
TCP_FLAG_CWR = 0x80

features_column=['Protocol', 'Flow Duration', 'Total Fwd Packets',
       'Total Backward Packets', 'Fwd Packet Length Max',
       'Fwd Packet Length Min', 'Fwd Packet Length Mean',
       'Fwd Packet Length Std', 'Bwd Packet Length Max',
       'Bwd Packet Length Min', 'Bwd Packet Length Mean',
       'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s',
       'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
       'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s',
       'Bwd Packets/s', 'Packet Length Mean', 'Packet Length Std',
       'Packet Length Variance', 'FIN Flag Count', 'SYN Flag Count',
       'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
       'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio',
       'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Subflow Fwd Packets',
       'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes']

class EnhancedDDoSDetector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(EnhancedDDoSDetector, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.flow_stats = {}
        self.blocked_ips = set()
        self.datapaths = {}
        self.logger.setLevel(logging.INFO)
        self.syn_counters = {}
        self.syn_threshold = 50
        self.syn_window = 3

        try:
            self.model = load_model("/home/garv/Desktop/Cyber-Security/Models/ddos_detection_model01.keras")
            self.scaler = joblib.load("/home/garv/Desktop/Cyber-Security/Models/scaler.pkl")
            self.logger.info("DDoS detection model loaded successfully.")
        except Exception as e:
            self.logger.warning(f"Failed to load DDoS detection model: {e}")
            self.logger.info("Continuing without model - will use basic SYN flood detection")
            self.model = None

        self.monitor_thread = hub.spawn(self._monitor)

    def _monitor(self):
        while True:
            current_time = time.time()
            # SYN flood detection based on counters
            for ip, data in list(self.syn_counters.items()):
                if current_time - data['first_seen'] > self.syn_window:
                    syn_rate = data['count'] / self.syn_window
                    if data['count'] > self.syn_threshold and ip not in self.blocked_ips:
                        self.blocked_ips.add(ip)
                        self.logger.info(f"[ALERT] SYN Flood Detected - IP: {ip}, Rate: {syn_rate:.2f} SYNs/sec")
                        self._block_ip(ip)
                    self.syn_counters[ip] = {'count': 0, 'first_seen': current_time}

            # ML-based detection
            if self.model:
                for key, flow in list(self.flow_stats.items()):
                    if current_time - flow['last_seen'] > 1:
                        features = self._extract_features(flow)
                        try:
                            sample = np.array(features).reshape(1, -1)
                            new_sample_df = pd.DataFrame(sample, columns=features_column)
                            sample_scaled = self.scaler.transform(new_sample_df)
                            prediction_prob = self.model.predict(sample_scaled)[0][0]
                            print(sample_scaled)
                            self.logger.info(f"DDoS probability score: {prediction_prob:.4f}")
                            threshold = 0.3
                            is_attack = prediction_prob >= threshold
                            # print(is_attack)
                            src_ip = key[0]
                            if is_attack and src_ip not in self.blocked_ips:
                                self.blocked_ips.add(src_ip)
                                self.logger.info(f"[ALERT] DDoS Detected via ML - IP: {src_ip}, Protocol: {flow['protocol']}")
                                self._block_ip(src_ip)
                        except Exception as e:
                            self.logger.warning(f"Prediction error: {e}")
                        del self.flow_stats[key]

            hub.sleep(1)

    def _extract_features(self, flow):
        duration = flow['last_seen'] - flow['first_seen']
        if duration <= 0:
            duration = 1e-6

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
            np.mean(flow['fwd_pkt_lengths']) if flow['fwd_pkt_lengths'] else 0,  
            np.mean(flow['bwd_pkt_lengths']) if flow['bwd_pkt_lengths'] else 0,  
            flow['subflow_fwd_packets'],  
            flow['subflow_fwd_bytes'],  
            flow['subflow_bwd_packets'],  
            flow['subflow_bwd_bytes'],  
        ]
        return features

    def _block_ip(self, ip):
        self.logger.info(f"Blocking IP: {ip}")
        for dp in self.datapaths.values():
            parser = dp.ofproto_parser
            match = parser.OFPMatch(ipv4_src=ip)
            actions = []  # Drop
            self.add_flow(dp, 100, match, actions)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.datapaths[datapath.id] = datapath

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        match = parser.OFPMatch(eth_type=0x0806)
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.add_flow(datapath, 100, match, actions)

        self.logger.info(f"Switch {datapath.id} connected and configured.")

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if eth_pkt.ethertype == 0x88cc:  # Ignore LLDP packets
            return

        dst = eth_pkt.dst
        src = eth_pkt.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # Learn MAC to port mapping
        self.mac_to_port[dpid][src] = in_port

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt:
            return

        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst
        protocol = ip_pkt.proto  # 6=TCP, 17=UDP, etc.

        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        flow_key = (src_ip, dst_ip, protocol)
        current_time = time.time()

        if flow_key not in self.flow_stats:
            self.flow_stats[flow_key] = {
                'first_seen': current_time,
                'last_seen': current_time,
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
                'protocol': protocol,
            }

        flow = self.flow_stats[flow_key]
        flow['last_seen'] = current_time

        # Determine direction (forward/backward)
        if src_ip == flow_key[0]:
            # Forward direction
            flow['fwd_packets'] += 1
            pkt_len = len(msg.data)
            flow['fwd_pkt_lengths'].append(pkt_len)
            flow['fwd_header_total_len'] += (len(pkt.protocols[1:]) if len(pkt.protocols) > 1 else 0)

            if tcp_pkt:
                flags = tcp_pkt.bits
                # Count flags in forward direction
                flow['fin_flag_count'] += 1 if (flags & TCP_FLAG_FIN) else 0
                flow['syn_flag_count'] += 1 if (flags & TCP_FLAG_SYN) else 0
                flow['rst_flag_count'] += 1 if (flags & TCP_FLAG_RST) else 0
                flow['psh_flag_count'] += 1 if (flags & TCP_FLAG_PSH) else 0
                flow['ack_flag_count'] += 1 if (flags & TCP_FLAG_ACK) else 0
                flow['urg_flag_count'] += 1 if (flags & TCP_FLAG_URG) else 0
                flow['cwe_flag_count'] += 1 if (flags & TCP_FLAG_CWR) else 0
                flow['ece_flag_count'] += 1 if (flags & TCP_FLAG_ECE) else 0

                # SYN flood counter for SYN packets
                if (flags & TCP_FLAG_SYN) and not (flags & TCP_FLAG_ACK):
                    if src_ip not in self.syn_counters:
                        self.syn_counters[src_ip] = {'count': 1, 'first_seen': current_time}
                    else:
                        self.syn_counters[src_ip]['count'] += 1

            # Check PSH and URG flags for forward direction
            flow['fwd_psh_flags'] += 1 if tcp_pkt and (tcp_pkt.bits & TCP_FLAG_PSH) else 0
            flow['fwd_urg_flags'] += 1 if tcp_pkt and (tcp_pkt.bits & TCP_FLAG_URG) else 0

            # Subflow updates
            flow['subflow_fwd_packets'] += 1
            flow['subflow_fwd_bytes'] += pkt_len

        else:
            # Backward direction
            flow['bwd_packets'] += 1
            pkt_len = len(msg.data)
            flow['bwd_pkt_lengths'].append(pkt_len)
            flow['bwd_header_total_len'] += (len(pkt.protocols[1:]) if len(pkt.protocols) > 1 else 0)

            if tcp_pkt:
                flags = tcp_pkt.bits
                # Count flags in backward direction
                # Note: Typically flags counts are aggregated, but you can maintain separate counts if needed.
                # Here we add to total counts as well.
                flow['fin_flag_count'] += 1 if (flags & TCP_FLAG_FIN) else 0
                flow['syn_flag_count'] += 1 if (flags & TCP_FLAG_SYN) else 0
                flow['rst_flag_count'] += 1 if (flags & TCP_FLAG_RST) else 0
                flow['psh_flag_count'] += 1 if (flags & TCP_FLAG_PSH) else 0
                flow['ack_flag_count'] += 1 if (flags & TCP_FLAG_ACK) else 0
                flow['urg_flag_count'] += 1 if (flags & TCP_FLAG_URG) else 0
                flow['cwe_flag_count'] += 1 if (flags & TCP_FLAG_CWR) else 0
                flow['ece_flag_count'] += 1 if (flags & TCP_FLAG_ECE) else 0

            # Check PSH and URG flags for backward direction
            flow['bwd_psh_flags'] += 1 if tcp_pkt and (tcp_pkt.bits & TCP_FLAG_PSH) else 0
            flow['bwd_urg_flags'] += 1 if tcp_pkt and (tcp_pkt.bits & TCP_FLAG_URG) else 0

            # Subflow updates
            flow['subflow_bwd_packets'] += 1
            flow['subflow_bwd_bytes'] += pkt_len

        # Install flow entry for known destination MAC if possible (basic L2 forwarding)
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
        self.add_flow(datapath, 1, match, actions, msg.buffer_id)

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
