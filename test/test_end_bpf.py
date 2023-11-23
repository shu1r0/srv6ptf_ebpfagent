from unittest import TestCase, main
from logging import getLogger
from scapy.all import *
from json import dumps

from nfagent.collector_grpc.collector_client import PacketCollectorClient

from srv6_ping.ping import ping1, new_srh_tlv


def fix_len_for_lwt_seg6local(pkt: IPv6, tlvlen: int) -> Optional[IPv6]:
    pkt[IPv6].plen += tlvlen
    if IPv6ExtHdrSegmentRouting in pkt:
        pkt[IPv6ExtHdrSegmentRouting].len += tlvlen // 8
        return IPv6(raw(pkt))

class TestEndBPF(TestCase):

    def setUp(self):
        """start gRPC client"""
        self.client = PacketCollectorClient(ip="192.168.10.1", port="31000", node_id=1, node_id_length=16,
                                            logger=getLogger(__name__),
                                            counter_length=32,
                                            enable_stats=True)
        self.client.establish_channel()
        self.packet_list = []
        self.packetid_list = []

        def notify_packet_handler(data):
            print("***** Received Packet from agent *****")
            print(data)
            self.packet_list.append(data)
            pkt = Ether(data["data"])
            if IPv6ExtHdrSegmentRoutingTLV in pkt:
                pkt[IPv6ExtHdrSegmentRoutingTLV].show()

        def notify_packetid_handler(data):
            print("***** Received PacketId from agent *****")
            self.packetid_list.append(data)
            print(data)

        def client_start():
            loop = self.client.event_loop
            loop.run_until_complete(
                self.client.notify_packet_info_coro(notify_packet_handler, notify_packetid_handler, True))

        self.client_thread = threading.Thread(target=client_start)
        self.client_thread.start()
    
    def check_lastreq_from_agent(self, results, header=Ether):
        sent_req = results[-1]["sent_pkt"][ICMPv6EchoRequest]
        recv_req_agent = header(self.packet_list[-1]["data"])[ICMPv6EchoRequest]
        self.assertEqual(bytes(sent_req.data), recv_req_agent.data)

    def check_lastreq_from_agent_seg6local(self, results):
        sent_req = results[-1]["sent_pkt"][ICMPv6EchoRequest]
        recv_req_agent = fix_len_for_lwt_seg6local(IPv6(self.packet_list[-1]["data"]), 8)[ICMPv6EchoRequest]
        self.assertEqual(bytes(sent_req.data), recv_req_agent.data)

    def test_srv6_ping_endbpf(self):
        results = []
        ping_times = 3
    
        # TimeExceed can't be received 
        print("Send packets ... (Get Timeout)")
        for _ in range(ping_times):
            result = ping1(dst="2001:db8:20::2", segs=["2001:db8:30::3"], hlim=1, return_pkt=True)
            if result:
                results.append(result)
        self.assertTrue(len(results) > 0)
        if len(results) > 0:
            for result in results:
                self.assertEqual("TimeExceeded", result["msg"])
                # check return_pkt
                self.assertTrue(result["sent_pkt"][IPv6].src == result["recv_pkt"][IPv6].dst)
                self.assertTrue(IPv6ExtHdrSegmentRoutingTLV in result["recv_pkt"])
            # TODO
            # self.check_lastreq_from_agent_seg6local(results)
        print("Send packets (Get Timeout): {}, Recieved packets: {}".format(ping_times, len(results)))
        
        print("Send packets ... (Get Reply)")
        results = []
        for _ in range(ping_times):
            result = ping1(dst="2001:db8:20::2", segs=["2001:db8:30::3"], hlim=64, return_pkt=True)
            if result:
                results.append(result)
        self.assertTrue(len(results) > 0)
        if len(results) > 0:
            for result in results:
                self.assertEqual("EchoReply", result["
                # TODOmsg"])
            # self.check_lastreq_from_agent_seg6local(results)
        print("Send packets (Get Reply): {}, Recieved packets: {}".format(ping_times, len(results)))

    def test_srv6_ping_pktid_tlv_endbpf(self):
        results = []
        ping_times = 3
        tlv = new_srh_tlv(type=124, value='\x00\x01\x00\x00\x00\x01')
        
        print("Send packets ... (Get Reply)")
        results = []
        for _ in range(ping_times):
            result = ping1(dst="2001:db8:20::2", segs=["2001:db8:30::3"], hlim=64, srh_tlvs=[tlv], return_pkt=True)
            if result:
                results.append(result)
        self.assertTrue(len(results) > 0)
        if len(results) > 0:
            for result in results:
                self.assertEqual("EchoReply", result["msg"])
        print("Send packets (Get Reply): {}, Recieved packets: {}".format(ping_times, len(results)))

    def test_srv6_ping_encap2endbpf(self):
        results = []
        ping_times = 3
    
        print("Send packets ... (Encap to Endbpf)")
        for _ in range(ping_times):
            result = ping1(dst="2001:db8:20::100", including_srh=False, hlim=64, return_pkt=True)
            if result:
                results.append(result)
        self.assertTrue(len(results) > 0)
        if len(results) > 0:
            for result in results:
                self.assertEqual("EchoReply", result["
                # TODOmsg"])
            # self.check_lastreq_from_agent_seg6local(results)
        print("Send packets (Encap to Endbpf): {}, Recieved packets: {}".format(ping_times, len(results)))

    def test_srv6_ping_pktid_tlv_xmit_readid(self):
        results = []
        ping_times = 3
        tlv = new_srh_tlv(type=124, value='\x00\x01\x00\x00\x00\x01')
        
        print("Send packets ... (Get Reply)")
        results = []
        for _ in range(ping_times):
            result = ping1(dst="2001:db8:20::3", hlim=64, srh_tlvs=[tlv], return_pkt=True)
            if result:
                results.append(result)
        self.assertTrue(len(results) > 0)
        if len(results) > 0:
            for result in results:
                # self.assertEqual("EchoReply", result["msg"])
                pass  # TODO
        print("Send packets (Get Reply): {}, Recieved packets: {}".format(ping_times, len(results)))

    def test_srv6_ping_pktid_tlv_in_readid(self):
        results = []
        ping_times = 3
        tlv = new_srh_tlv(type=124, value='\x00\x01\x00\x00\x00\x01')
        
        print("Send packets ... (Get Reply)")
        results = []
        for _ in range(ping_times):
            result = ping1(dst="2001:db8:20::4", hlim=64, srh_tlvs=[tlv], return_pkt=True)
            if result:
                results.append(result)
        self.assertTrue(len(results) > 0)
        if len(results) > 0:
            for result in results:
                # self.assertEqual("EchoReply", result["msg"])
                pass  # TODO
        print("Send packets (Get Reply): {}, Recieved packets: {}".format(ping_times, len(results)))

    def test_srv6_ping_pktid_tlv_out_readid(self):
        results = []
        ping_times = 3
        tlv = new_srh_tlv(type=124, value='\x00\x01\x00\x00\x00\x01')
        
        print("Send packets ... (Get Reply)")
        results = []
        for _ in range(ping_times):
            result = ping1(dst="2001:db8:20::5", hlim=64, srh_tlvs=[tlv], return_pkt=True)
            if result:
                results.append(result)
        self.assertTrue(len(results) > 0)
        if len(results) > 0:
            for result in results:
                # self.assertEqual("EchoReply", result["msg"])
                pass  # TODO
        print("Send packets (Get Reply): {}, Recieved packets: {}".format(ping_times, len(results)))

    def tearDown(self):
        self.client.close_channel()
        self.client_thread.join(1)
