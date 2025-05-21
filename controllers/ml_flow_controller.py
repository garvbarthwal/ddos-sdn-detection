from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, icmp, tcp, udp
from ryu.lib import hub
import numpy as np
import tensorflow as tf
from tensorflow import keras
import time
import logging
import pandas as pd
from collections import defaultdict

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('DDOSDefender')


class DDOSDefender(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DDOSDefender, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        
        # Flow statistics collection
        self.flow_stats = defaultdict(lambda: defaultdict(dict))
        
        # For feature extraction
        self.packet_counts = defaultdict(lambda: defaultdict(int))
        self.packet_sizes = defaultdict(lambda: defaultdict(list))
        self.flow_timestamps = defaultdict(lambda: defaultdict(list))
        self.protocol_counts = defaultdict(lambda: defaultdict(int))
        
        # Blacklisted IPs (detected attackers)
        self.blacklisted_ips = set()
        
        # Load the Keras model
        try:
            logger.info("Loading Keras DDoS detection model...")
            # Try with both potential model files in the workspace
            try:
                self.model = keras.models.load_model('model.h5', compile=False)
                logger.info("Model loaded successfully from model.h5")
            except:
                self.model = keras.models.load_model('model2.keras', compile=False)
                logger.info("Model loaded successfully from model2.keras")
        except Exception as e:
            logger.error(f"Failed to load model: {str(e)}")
            self.model = None
            
        # Feature names - important to have this match your model's expected inputs
        self.feature_names = [
            'packet_count', 'avg_packet_size', 'std_packet_size', 
            'flow_duration', 'packet_rate', 'byte_rate',
            'tcp_count', 'udp_count', 'icmp_count'
        ]
        
        logger.info("DDOSDefender initialized")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle switch connection event and install table-miss flow entry"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Store datapath for monitoring
        self.datapaths[datapath.id] = datapath
        
        # Install the table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        logger.info(f"Switch {datapath.id} connected")

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, hard_timeout=0, idle_timeout=0):
        """Add a flow entry to the switch"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, hard_timeout=hard_timeout,
                                    idle_timeout=idle_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    hard_timeout=hard_timeout,
                                    idle_timeout=idle_timeout)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """Handle incoming packets"""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        # Ignore LLDP packets
        if eth.ethertype == 0x88cc:
            return
            
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        
        # Create entry for this datapath in MAC table if it doesn't exist
        if dpid not in self.mac_to_port:
            self.mac_to_port[dpid] = {}
            
        # Learn MAC address to avoid FLOOD
        self.mac_to_port[dpid][src] = in_port
        
        # Extract IP header if present
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            proto = ip_pkt.proto
            
            # Check if source IP is blacklisted
            if src_ip in self.blacklisted_ips:
                logger.info(f"Blocked packet from blacklisted IP: {src_ip}")
                return
                
            # Allow PING (ICMP) traffic without restrictions
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            if icmp_pkt:
                # Update statistics for ICMP
                self._update_flow_stats(src_ip, dst_ip, 'icmp', len(pkt), time.time())
                
                # Allow ICMP traffic to pass through
                self._forward_packet(msg, datapath, in_port, eth, dst)
                return
                
            # For TCP and UDP, collect statistics and trigger detection if needed
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)
            
            if tcp_pkt:
                self._update_flow_stats(src_ip, dst_ip, 'tcp', len(pkt), time.time())
            elif udp_pkt:
                self._update_flow_stats(src_ip, dst_ip, 'udp', len(pkt), time.time())
            
            # Check for potential attack pattern every 10 packets from same source
            flow_key = (src_ip, dst_ip)
            packets_count = self.packet_counts[flow_key]
            total_packets = sum(packets_count.values())
            
            if total_packets > 0 and total_packets % 10 == 0:
                is_attack = self._detect_attack(flow_key)
                if is_attack:
                    logger.warning(f"Attack detected from {src_ip}! Blocking...")
                    self.blacklisted_ips.add(src_ip)
                    self._install_drop_flow(datapath, src_ip)
                    return
                    
        # Forward the packet if not blocked
        self._forward_packet(msg, datapath, in_port, eth, dst)

    def _forward_packet(self, msg, datapath, in_port, eth, dst):
        """Forward packet based on MAC learning"""
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Check if destination MAC is already learned
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
            
        actions = [parser.OFPActionOutput(out_port)]
        
        # Install flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=eth.src)
            # Flow expires after 30 seconds of inactivity
            self.add_flow(datapath, 1, match, actions, idle_timeout=30)
            
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
            
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _update_flow_stats(self, src_ip, dst_ip, proto, packet_size, timestamp):
        """Update flow statistics for feature extraction"""
        flow_key = (src_ip, dst_ip)
        
        # Update packet counts
        self.packet_counts[flow_key][proto] += 1
        
        # Update packet sizes
        self.packet_sizes[flow_key][proto].append(packet_size)
        
        # Update timestamps
        self.flow_timestamps[flow_key][proto].append(timestamp)
        
        # Update protocol counts
        self.protocol_counts[flow_key][proto] += 1

    def _extract_features(self, flow_key):
        """Extract features for DDoS detection"""
        # Initialize feature dictionary
        features = {}
        
        # Total packet count for this flow
        features['packet_count'] = sum(self.packet_counts[flow_key].values())
        
        # Combine all packet sizes across protocols
        all_packet_sizes = []
        for proto in ['tcp', 'udp', 'icmp']:
            all_packet_sizes.extend(self.packet_sizes[flow_key][proto])
        
        # Packet size statistics
        if all_packet_sizes:
            features['avg_packet_size'] = np.mean(all_packet_sizes)
            features['std_packet_size'] = np.std(all_packet_sizes) if len(all_packet_sizes) > 1 else 0
        else:
            features['avg_packet_size'] = 0
            features['std_packet_size'] = 0
        
        # Flow duration
        all_timestamps = []
        for proto in ['tcp', 'udp', 'icmp']:
            all_timestamps.extend(self.flow_timestamps[flow_key][proto])
        
        if len(all_timestamps) > 1:
            features['flow_duration'] = max(all_timestamps) - min(all_timestamps)
            # Rate features
            features['packet_rate'] = features['packet_count'] / features['flow_duration'] if features['flow_duration'] > 0 else 0
            features['byte_rate'] = sum(all_packet_sizes) / features['flow_duration'] if features['flow_duration'] > 0 else 0
        else:
            features['flow_duration'] = 0
            features['packet_rate'] = 0
            features['byte_rate'] = 0
        
        # Protocol counts
        features['tcp_count'] = self.packet_counts[flow_key]['tcp']
        features['udp_count'] = self.packet_counts[flow_key]['udp']
        features['icmp_count'] = self.packet_counts[flow_key]['icmp']
        
        return features

    def _detect_attack(self, flow_key):
        """Detect if a flow is a DDoS attack using the loaded model"""
        if self.model is None:
            logger.error("Cannot perform detection, model not loaded")
            return False
            
        # Extract features
        features = self._extract_features(flow_key)
        logger.info(f"Extracted features for {flow_key}: {features}")
        
        # Convert features to DataFrame for model prediction
        # Ensure the order matches what the model expects
        feature_vector = [features[feature] for feature in self.feature_names]
        X = np.array([feature_vector])
        
        # Make prediction
        try:
            prediction = self.model.predict(X)
            is_attack = bool(prediction[0][0] > 0.5)  # Assuming binary classification
            logger.info(f"Prediction for {flow_key}: {prediction[0][0]}, classified as attack: {is_attack}")
            return is_attack
        except Exception as e:
            logger.error(f"Error making prediction: {str(e)}")
            return False

    def _install_drop_flow(self, datapath, src_ip):
        """Install a flow rule to drop all traffic from a specific IP"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Create a match for the source IP
        match = parser.OFPMatch(ipv4_src=src_ip)
        
        # No actions means drop
        actions = []
        
        # Install with high priority (100) and timeout of 300 seconds (5 minutes)
        self.add_flow(datapath, 100, match, actions, hard_timeout=300)
        logger.warning(f"Installed drop flow for attacker IP: {src_ip}")

    def _monitor(self):
        """Periodically monitor flows and clear old statistics"""
        while True:
            hub.sleep(30)  # Monitor every 30 seconds
            
            # Clear old flow statistics to prevent memory bloat
            current_time = time.time()
            flows_to_remove = []
            
            for flow_key in self.flow_timestamps:
                all_timestamps = []
                for proto in ['tcp', 'udp', 'icmp']:
                    all_timestamps.extend(self.flow_timestamps[flow_key][proto])
                
                if all_timestamps and (current_time - max(all_timestamps)) > 60:
                    # Flow inactive for more than 60 seconds
                    flows_to_remove.append(flow_key)
            
            # Remove old flows
            for flow_key in flows_to_remove:
                del self.packet_counts[flow_key]
                del self.packet_sizes[flow_key]
                del self.flow_timestamps[flow_key]
                del self.protocol_counts[flow_key]
                
            logger.info(f"Monitor cycle completed. Cleared {len(flows_to_remove)} inactive flows.")
            
            # Every 5 minutes, clear the blacklist to allow redemption
            if int(current_time) % 300 < 30:
                old_count = len(self.blacklisted_ips)
                self.blacklisted_ips.clear()
                logger.info(f"Cleared {old_count} IPs from blacklist")