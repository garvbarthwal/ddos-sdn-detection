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

        self.packet_counts = defaultdict(lambda: defaultdict(int))
        self.packet_sizes = defaultdict(lambda: defaultdict(list))
        self.flow_timestamps = defaultdict(lambda: defaultdict(list))

        self.blacklisted_ips = set()
        self.last_blacklist_clear = time.time()

        # Load the Keras model
        try:
            logger.info("Loading Keras DDoS detection model...")
            try:
                self.model = keras.models.load_model('/home/garv/Desktop/Cyber-Security/model.h5', compile=False)
                logger.info("Model loaded from model.h5")
            except Exception:
                self.model = keras.models.load_model('/home/garv/Desktop/Cyber-Security/model2.keras', compile=False)
                logger.info("Model loaded from model2.keras")
        except Exception as e:
            logger.error(f"Model loading failed: {str(e)}")
            self.model = None

        self.feature_names = [
            'packet_count', 'avg_packet_size', 'std_packet_size',
            'flow_duration', 'packet_rate', 'byte_rate',
            'tcp_count', 'udp_count', 'icmp_count'
        ]

        logger.info("DDOSDefender initialized and running")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.datapaths[datapath.id] = datapath
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        logger.info(f"Switch connected: ID {datapath.id}")

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, hard_timeout=0, idle_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst,
                                    hard_timeout=hard_timeout, idle_timeout=idle_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    hard_timeout=hard_timeout, idle_timeout=idle_timeout)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth.ethertype == 0x88cc:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        if dpid not in self.mac_to_port:
            self.mac_to_port[dpid] = {}
        self.mac_to_port[dpid][src] = in_port

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            proto = ip_pkt.proto

            if src_ip in self.blacklisted_ips:
                logger.info(f"Dropped packet from blacklisted IP: {src_ip}")
                return

            icmp_pkt = pkt.get_protocol(icmp.icmp)
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)

            if icmp_pkt:
                self._update_flow_stats(src_ip, dst_ip, 'icmp', len(msg.data), time.time())
                self._forward_packet(msg, datapath, in_port, eth, dst)
                return
            if tcp_pkt:
                self._update_flow_stats(src_ip, dst_ip, 'tcp', len(msg.data), time.time())
            elif udp_pkt:
                self._update_flow_stats(src_ip, dst_ip, 'udp', len(msg.data), time.time())

            flow_key = (src_ip, dst_ip)
            total_packets = sum(self.packet_counts[flow_key].values())

            if total_packets > 0 and total_packets % 10 == 0:
                is_attack = self._detect_attack(flow_key)
                if is_attack:
                    logger.warning(f"DDoS Detected from {src_ip} — blacklisting and dropping.")
                    self.blacklisted_ips.add(src_ip)
                    self._install_drop_flow(datapath, src_ip)
                    return

        self._forward_packet(msg, datapath, in_port, eth, dst)

    def _forward_packet(self, msg, datapath, in_port, eth, dst):
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=eth.src)
            self.add_flow(datapath, 1, match, actions, idle_timeout=30)

        data = None if msg.buffer_id != ofproto.OFP_NO_BUFFER else msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _update_flow_stats(self, src_ip, dst_ip, proto, packet_size, timestamp):
        flow_key = (src_ip, dst_ip)
        self.packet_counts[flow_key][proto] += 1
        self.packet_sizes[flow_key][proto].append(packet_size)
        self.flow_timestamps[flow_key][proto].append(timestamp)

    def _extract_features(self, flow_key):
        features = {}
        features['packet_count'] = sum(self.packet_counts[flow_key].values())

        all_packet_sizes = []
        for proto in ['tcp', 'udp', 'icmp']:
            all_packet_sizes.extend(self.packet_sizes[flow_key][proto])
        features['avg_packet_size'] = np.mean(all_packet_sizes) if all_packet_sizes else 0
        features['std_packet_size'] = np.std(all_packet_sizes) if len(all_packet_sizes) > 1 else 0

        all_timestamps = []
        for proto in ['tcp', 'udp', 'icmp']:
            all_timestamps.extend(self.flow_timestamps[flow_key][proto])
        if len(all_timestamps) > 1:
            duration = max(all_timestamps) - min(all_timestamps)
            features['flow_duration'] = duration
            features['packet_rate'] = features['packet_count'] / duration if duration > 0 else 0
            total_bytes = sum(all_packet_sizes)
            features['byte_rate'] = total_bytes / duration if duration > 0 else 0
        else:
            features['flow_duration'] = 0
            features['packet_rate'] = 0
            features['byte_rate'] = 0

        for proto in ['tcp', 'udp', 'icmp']:
            features[f'{proto}_count'] = self.packet_counts[flow_key][proto]

        return [features[name] for name in self.feature_names]

    def _detect_attack(self, flow_key):
        if self.model is None:
            logger.error("Model not loaded. Skipping detection.")
            return False

        features = self._extract_features(flow_key)
        features = np.array(features).reshape(1, -1)

        pred = self.model.predict(features, verbose=0)
        pred_label = np.argmax(pred, axis=1)[0]

        logger.info(f"Flow {flow_key} → Prediction: {pred_label}, Probs: {pred}")
        return pred_label == 1

    def _install_drop_flow(self, datapath, src_ip):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        actions = []
        self.add_flow(datapath, 10, match, actions, idle_timeout=300)

        logger.info(f"Installed DROP flow for blacklisted IP: {src_ip}")

    def _monitor(self):
        while True:
            current_time = time.time()
            if current_time - self.last_blacklist_clear > 300:
                logger.info("Clearing old blacklisted IPs...")
                self.blacklisted_ips.clear()
                self.last_blacklist_clear = current_time
            hub.sleep(1)
