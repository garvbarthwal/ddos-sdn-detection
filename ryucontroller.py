from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp
from ryu.lib import hub
import time
import numpy as np
from collections import defaultdict

class DDoSDetector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DDoSDetector, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.flow_stats = defaultdict(lambda: {'packet_count': 0, 'byte_count': 0, 'duration': 0})
        self.flow_history = defaultdict(list)  # Store historical flow data
        self.blacklisted_ips = set()
        
        # Feature thresholds for DDoS detection
        self.pkt_threshold = 500  # packets per monitoring interval
        self.byte_threshold = 10000  # bytes per monitoring interval
        self.monitoring_interval = 5  # seconds
        
        # Start monitoring thread
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]
    
    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(self.monitoring_interval)
    
    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
        
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)
    
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        
        for stat in body:
            if 'ipv4_src' in stat.match and 'ipv4_dst' in stat.match:
                key = (stat.match['ipv4_src'], stat.match['ipv4_dst'])
                
                # Get previous counter values
                prev_packets = self.flow_stats[key].get('packet_count', 0)
                prev_bytes = self.flow_stats[key].get('byte_count', 0)
                prev_duration = self.flow_stats[key].get('duration', 0)
                
                # Calculate differentials
                packet_diff = stat.packet_count - prev_packets
                byte_diff = stat.byte_count - prev_bytes
                duration_diff = stat.duration_sec - prev_duration
                
                # Update current values
                self.flow_stats[key] = {
                    'packet_count': stat.packet_count,
                    'byte_count': stat.byte_count,
                    'duration': stat.duration_sec
                }
                
                # Store metrics for analysis
                if duration_diff > 0:
                    pps = packet_diff / duration_diff  # packets per second
                    bps = byte_diff / duration_diff    # bytes per second
                    
                    self.flow_history[key].append({
                        'timestamp': time.time(),
                        'pps': pps,
                        'bps': bps
                    })
                    
                    # Keep history limited to last 10 monitoring intervals
                    if len(self.flow_history[key]) > 10:
                        self.flow_history[key].pop(0)
                    
                    # DDoS detection based on simple thresholds
                    if pps > self.pkt_threshold or bps > self.byte_threshold:
                        src_ip = stat.match['ipv4_src']
                        self.logger.info(f"Potential DDoS detected from {src_ip}! pps={pps:.2f}, bps={bps:.2f}")
                        
                        # Mitigate: Add source IP to blacklist
                        self.blacklisted_ips.add(src_ip)
                        
                        # Install drop rules for the attacking IP
                        self._install_blacklist_flow(ev.msg.datapath, src_ip)

    def _install_blacklist_flow(self, datapath, ip_addr):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Match on the blacklisted IP
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_addr)
        
        # No actions means drop
        self.add_flow(datapath, 100, match, [])  # High priority
        self.logger.info(f"Installed drop rule for {ip_addr}")
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install the table-miss flow entry to send unmatched packets to the controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                        ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                            actions)]
        if buffer_id:
            if timeout > 0:
                mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, hard_timeout=timeout)
            else:
                mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            if timeout > 0:
                mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, 
                                    hard_timeout=timeout)
            else:
                mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        # Check for IPv4 traffic
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt:
            # Check if source IP is in blacklist
            if ipv4_pkt.src in self.blacklisted_ips:
                # Drop silently
                return
        
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # Learn a MAC address to avoid flooding in the future
        self.mac_to_port[dpid][src] = in_port

        # Check the output port for the destination MAC address
        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)

        actions = [parser.OFPActionOutput(out_port)]

        # Extract features for flow
        if ipv4_pkt:
            # Record this packet in our stats
            flow_key = (ipv4_pkt.src, ipv4_pkt.dst)
            self.flow_stats[flow_key]['packet_count'] += 1
            self.flow_stats[flow_key]['byte_count'] += len(msg.data)
        
        # Install a flow entry to avoid future packet_in events
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        # If no flow entry was installed, send the packet out to the appropriate port
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)