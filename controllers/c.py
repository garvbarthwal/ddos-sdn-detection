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
        self.datapaths = {}  # Track connected datapaths
        
        # Enhanced logging
        self.logger.setLevel(logging.INFO)
        
        # SYN flood specific counters
        self.syn_counters = {}  # Track SYN packets per source IP
        self.syn_threshold = 50  # Alert if more than 50 SYN packets in window
        self.syn_window = 3  # Time window in seconds
        
        # Load your trained Keras model here
        try:
            self.model = load_model("/home/garv/Desktop/Cyber-Security/Models/ddos_detection_model01.keras")
            self.scaler = joblib.load("/home/garv/Desktop/Cyber-Security/Models/scaler.pkl")
            self.logger.info("DDoS detection model loaded successfully.")
        except Exception as e:
            self.logger.warning(f"Failed to load DDoS detection model: {e}")
            self.logger.info("Continuing without model - will use basic SYN flood detection")
            self.model = None

        # Spawn a monitoring thread to periodically process flows
        self.monitor_thread = hub.spawn(self._monitor)

    def _monitor(self):
        while True:
            current_time = time.time()
            
            # Process SYN counters for basic SYN flood detection
            for ip, data in list(self.syn_counters.items()):
                if current_time - data['first_seen'] > self.syn_window:
                    syn_rate = data['count'] / self.syn_window
                    if data['count'] > self.syn_threshold and ip not in self.blocked_ips:
                        self.blocked_ips.add(ip)
                        self.logger.info(f"[ALERT] SYN Flood Detected - IP: {ip}, Rate: {syn_rate:.2f} SYNs/sec, Window: {self.syn_window}s")
                        
                        # Here we could install block rules on switches
                        self._block_ip(ip)
                    
                    # Reset counter after window expires
                    self.syn_counters[ip] = {'count': 0, 'first_seen': current_time}
            
            # ML-based DDoS detection if model is available
            if self.model:
                for key, flow in list(self.flow_stats.items()):
                    if current_time - flow['last_seen'] > 1:
                        features = self._extract_features(flow)
                        try:
                            # Prepare the sample
                            sample = np.array(features).reshape(1, -1)
                            self.logger.debug("Input sample shape: %s", sample.shape)

                            # Check scaler expected features
                            self.logger.debug("Scaler features: %s", getattr(self.scaler, 'feature_names_in_', None))
                            self.logger.debug("Input features: %s", features_column)

                            new_sample_df = pd.DataFrame(sample, columns=features_column)

                            # Transform
                            sample_scaled = self.scaler.transform(new_sample_df)

                            # Predict
                            prediction_prob = self.model.predict(sample_scaled)[0][0]

                            self.logger.info(f"DDoS probability score: {prediction_prob:.4f}")
                            
                            # Use a threshold to determine if this is an attack
                            # Lower threshold (like 0.3) increases sensitivity but may cause false positives
                            threshold = 0.3  # Adjust based on your needs
                            is_attack = prediction_prob >= threshold
                            
                            src_ip = key[0]
                            
                            if is_attack and src_ip not in self.blocked_ips:
                                self.blocked_ips.add(src_ip)
                                self.logger.info(f"[ALERT] DDoS Detected via ML - IP: {src_ip}, Protocol: {flow['protocol']}, Time: {time.ctime()}")
                                self._block_ip(src_ip)

                        except Exception as e:
                            self.logger.warning(f"Prediction error: {e}")

                        # Clean up old flows after processing
                        del self.flow_stats[key]

            # Sleep for 1 second before next check
            hub.sleep(1)

    def _extract_features(self, flow):
        # Calculate duration (avoid zero division)
        duration = flow['last_seen'] - flow['first_seen']
        if duration <= 0:
            duration = 1e-6

        total_fwd = flow['fwd_packets']
        total_bwd = flow['bwd_packets']
        total_fwd_bytes = sum(flow['fwd_pkt_lengths'])
        total_bwd_bytes = sum(flow['bwd_pkt_lengths'])
        all_lengths = flow['fwd_pkt_lengths'] + flow['bwd_pkt_lengths']

        features = [
            flow['protocol'],  #1. Protocol
            duration,  #2. Flow Duration
            total_fwd,  #3. Total Fwd Packets
            total_bwd,  #4. Total Backward Packets
            max(flow['fwd_pkt_lengths'], default=0),  #5. Fwd Packet Length Max
            min(flow['fwd_pkt_lengths'], default=0),  #6. Fwd Packet Length Min
            np.mean(flow['fwd_pkt_lengths']) if flow['fwd_pkt_lengths'] else 0,  #7. Fwd Packet Length Mean
            np.std(flow['fwd_pkt_lengths']) if flow['fwd_pkt_lengths'] else 0,  #8. Fwd Packet Length Std
            max(flow['bwd_pkt_lengths'], default=0),  #9. Bwd Packet Length Max
            min(flow['bwd_pkt_lengths'], default=0),  #10. Bwd Packet Length Min
            np.mean(flow['bwd_pkt_lengths']) if flow['bwd_pkt_lengths'] else 0,  #11. Bwd Packet Length Mean
            np.std(flow['bwd_pkt_lengths']) if flow['bwd_pkt_lengths'] else 0,  #12. Bwd Packet Length Std
            (total_fwd_bytes + total_bwd_bytes) / duration,  #13. Flow Bytes/s
            (total_fwd + total_bwd) / duration,  #14. Flow Packets/s
            flow['fwd_psh_flags'],  #15. Fwd PSH Flags
            flow['bwd_psh_flags'],  #16. Bwd PSH Flags
            flow['fwd_urg_flags'],  #17. Fwd URG Flags
            flow['bwd_urg_flags'],  #18. Bwd URG Flags
            flow['fwd_header_total_len'],  #19. Fwd Header Length
            flow['bwd_header_total_len'],  #20. Bwd Header Length
            total_fwd / duration,  #21. Fwd Packets/s
            total_bwd / duration,  #22. Bwd Packets/s
            np.mean(all_lengths) if all_lengths else 0,  #23. Packet Length Mean
            np.std(all_lengths) if all_lengths else 0,  #24. Packet Length Std
            np.var(all_lengths) if all_lengths else 0,  #25. Packet Length Variance
            flow['fin_flag_count'],  #26. FIN Flag Count
            flow['syn_flag_count'],  #27. SYN Flag Count
            flow['rst_flag_count'],  #28. RST Flag Count
            flow['psh_flag_count'],  #29. PSH Flag Count
            flow['ack_flag_count'],  #30. ACK Flag Count
            flow['urg_flag_count'],  #31. URG Flag Count
            flow['cwe_flag_count'],  #32. CWE Flag Count
            flow['ece_flag_count'],  #33. ECE Flag Count
            total_bwd / total_fwd if total_fwd > 0 else 0,  #34. Down/Up Ratio
            np.mean(flow['fwd_pkt_lengths']) if flow['fwd_pkt_lengths'] else 0,  #35. Avg Fwd Segment Size
            np.mean(flow['bwd_pkt_lengths']) if flow['bwd_pkt_lengths'] else 0,  #36. Avg Bwd Segment Size
            flow['subflow_fwd_packets'],  #37. Subflow Fwd Packets
            flow['subflow_fwd_bytes'],  #38. Subflow Fwd Bytes
            flow['subflow_bwd_packets'],  #39. Subflow Bwd Packets
            flow['subflow_bwd_bytes'],  #40. Subflow Bwd Bytes
        ]
        return features
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Register datapath
        self.datapaths[datapath.id] = datapath

        # Install table-miss flow entry to send unmatched packets to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
        # Add a flow rule to allow ARP packets (for address resolution)
        match = parser.OFPMatch(eth_type=0x0806)  # ARP
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.add_flow(datapath, 100, match, actions)
        
        self.logger.info(f"Switch {datapath.id} connected and configured with default rules.")
        self.logger.info(f"Switch {datapath.id} connected and configured with default rules.")

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
        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        # Check if packet is ARP
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self._handle_arp(datapath, in_port, eth, arp_pkt)
            return
            
        if eth.ethertype != 0x0800:
            # Only analyze IPv4 packets for DDoS
            # But make sure to forward the packet
            self._handle_l2_packet(msg, datapath, in_port, eth)
            return

        ip = pkt.get_protocol(ipv4.ipv4)
        if ip is None:
            self._handle_l2_packet(msg, datapath, in_port, eth)
            return

        if ip.src in self.blocked_ips:
            # Drop packets from blocked IPs silently
            self.logger.debug(f"Dropping packet from blocked IP: {ip.src}")
            return

        # Check for TCP SYN packets for SYN flood detection
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        if tcp_pkt and tcp_pkt.bits & 0x02:  # SYN flag is set
            # Track SYN packets for basic SYN flood detection
            if ip.src not in self.syn_counters:
                self.syn_counters[ip.src] = {'count': 1, 'first_seen': time.time()}
            else:
                self.syn_counters[ip.src]['count'] += 1
                
            # Print debug info for SYN packets
            self.logger.debug(f"SYN packet from {ip.src} to {ip.dst} (count: {self.syn_counters[ip.src]['count']})")

        # Process packet for DDoS monitoring
        proto = ip.proto
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
                'init_win_bytes_fwd': getattr(tcp_pkt, 'window', 0) if tcp_pkt else 0,
                'init_win_bytes_bwd': 0,
                'act_data_pkt_fwd': 0,
                'min_seg_size_fwd': tcp_pkt.offset if tcp_pkt else 0
            }

        flow = self.flow_stats[key]
        flow['last_seen'] = now
        length = len(msg.data)

        # Determine direction: you used (in_port % 2) == 0 heuristic, keep it for now
        if (in_port % 2) == 0:
            # Forward direction
            flow['fwd_packets'] += 1
            flow['fwd_pkt_lengths'].append(length)
            flow['subflow_fwd_packets'] += 1
            flow['subflow_fwd_bytes'] += length
            flow['act_data_pkt_fwd'] += 1

            if tcp_pkt:
                flags = tcp_pkt.bits
                flow['fwd_psh_flags'] += int(flags & 0x08 != 0)
                flow['fwd_urg_flags'] += int(flags & 0x20 != 0)
                flow['fwd_header_total_len'] += tcp_pkt.offset * 4
                flow['fin_flag_count'] += int(flags & 0x01 != 0)
                flow['syn_flag_count'] += int(flags & 0x02 != 0)
                flow['rst_flag_count'] += int(flags & 0x04 != 0)
                flow['psh_flag_count'] += int(flags & 0x08 != 0)
                flow['ack_flag_count'] += int(flags & 0x10 != 0)
                flow['urg_flag_count'] += int(flags & 0x20 != 0)
                flow['cwe_flag_count'] += int(flags & 0x40 != 0)
                flow['ece_flag_count'] += int(flags & 0x80 != 0)
        else:
            # Backward direction
            flow['bwd_packets'] += 1
            flow['bwd_pkt_lengths'].append(length)
            flow['subflow_bwd_packets'] += 1
            flow['subflow_bwd_bytes'] += length

            if tcp_pkt:
                flags = tcp_pkt.bits
                flow['bwd_psh_flags'] += int(flags & 0x08 != 0)
                flow['bwd_urg_flags'] += int(flags & 0x20 != 0)
                flow['bwd_header_total_len'] += tcp_pkt.offset * 4

        # Forward packet - critical for connectivity
        self._handle_l2_packet(msg, datapath, in_port, eth)

    def _handle_arp(self, datapath, in_port, eth, arp_pkt):
        """Handle ARP packets"""
        # Flood ARP packets (simplified)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # This is critical for IP resolution to work properly
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        data = None
        if datapath.ofproto.OFP_NO_BUFFER:
            data = eth.payload

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _handle_l2_packet(self, msg, datapath, in_port, eth):
        """Forward packet using L2 learning switch logic"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        
        # Learn MAC-to-port mapping
        dst = eth.dst
        src = eth.src
        
        # Initialize mac_to_port for this datapath if needed
        self.mac_to_port.setdefault(dpid, {})
        
        # Learn the port where this source MAC was seen
        self.mac_to_port[dpid][src] = in_port
        
        # If we know the destination MAC, send the packet there
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            # Otherwise, flood the packet
            out_port = ofproto.OFPP_FLOOD
            
        actions = [parser.OFPActionOutput(out_port)]
        
        # Install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # Check if we have a valid buffer_id
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        
        # Send packet out message
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
            
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data
        )
        datapath.send_msg(out)

    def _block_ip(self, ip):
        """Block an IP on all connected switches"""
        self.logger.info(f"Installing blocking rules for IP {ip} on all switches")
        
        for dpid, datapath in self.dpidToDatapath().items():
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            
            # Create match for this IP (both directions to completely block the host)
            match_src = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
            match_dst = parser.OFPMatch(eth_type=0x0800, ipv4_dst=ip)
            
            # Empty actions list means drop
            actions = []
            
            # Add high priority flow rules to drop packets
            self.add_flow(datapath, 150, match_src, actions)
    def dpidToDatapath(self):
        return self.datapaths

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, 'DEAD_DISPATCHER'])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
        elif ev.state == 'DEAD_DISPATCHER':
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
            self.logger.info(f"Blocking rules installed on switch {dpid} for IP {ip}")
            
    def dpidToDatapath(self):
        return self.datapaths