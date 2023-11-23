from unittest import TestCase, main
from logging import getLogger
from scapy.all import *
from json import dumps
from time import sleep

from nfagent.collector_grpc.collector_client import PacketCollectorClient

from srv6_ping.ping import ping1, new_srh_tlv


class TestSPacket(TestCase):

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
    
    def test_srv6_ping(self):
        results = []
        ping_times = 3
        
        print("Send packets ... (Get Timeout)")
        for _ in range(ping_times):
            result = ping1(dst="2001:db8:20::2", segs=["2001:db8:10::1"], hlim=1, return_pkt=True)
            if result:
                results.append(result)
        self.assertTrue(len(results) > 0)
        if len(results) > 0:
            for result in results:
                self.assertEqual("TimeExceeded", result["msg"])
                # check return_pkt
                self.assertTrue(result["sent_pkt"][IPv6].src == result["recv_pkt"][IPv6].dst)
                self.assertTrue(IPv6ExtHdrSegmentRoutingTLV in result["recv_pkt"])
            # TODO: packet_list == 2 ???
            self.assertGreaterEqual(len(self.packet_list), len(results)-1)
        print("Send packets (Get Timeout): {}, Recieved packets: {}".format(ping_times, len(results)))
        
        print("Send packets ... (Get Reply)")
        results = []
        for _ in range(ping_times):
            result = ping1(dst="2001:db8:20::2", segs=["2001:db8:10::1"], hlim=64, return_pkt=True)
            if result:
                results.append(result)
        self.assertTrue(len(results) > 0)
        if len(results) > 0:
            for result in results:
                self.assertEqual("EchoReply", result["msg"])
        print("Send packets (Get Reply): {}, Recieved packets: {}".format(ping_times, len(results)))
        
        print("Send packets for Engress Hook ... (Get Reply)")
        results = []
        for _ in range(ping_times):
            result = ping1(dst="2001:db8:20::100", including_srh=False, hlim=64, return_pkt=True)
            if result:
                results.append(result)
        self.assertTrue(len(results) > 0)
        if len(results) > 0:
            for result in results:
                self.assertEqual("EchoReply", result["msg"])
        print("Send packets (Get Reply): {}, Recieved packets: {}".format(ping_times, len(results)))
    
    def test_srv6_ping_pktid_tlv(self):
        results = []
        ping_times = 3
        tlv_value = b'\x00\x01\x00\x00\x00\x01'
        tlv_value_int = int.from_bytes(tlv_value, "big")
        tlv = new_srh_tlv(type=124, value=tlv_value)
        
        print("Send packets ... (Get Reply)")
        results = []
        for _ in range(ping_times):
            result = ping1(dst="2001:db8:20::2", segs=["2001:db8:10::1"], hlim=64, srh_tlvs=[tlv], return_pkt=True)
            if result:
                results.append(result)
        self.assertTrue(len(results) > 0)
        if len(results) > 0:
            for result in results:
                self.assertEqual("EchoReply", result["msg"])
            self.assertIn(tlv_value_int, [pkt["pkt_id"] for pkt in self.packetid_list])
        print("Send packets (Get Reply): {}, Recieved packets: {}".format(ping_times, len(results)))
    
    def test_large_ping(self):
        results = []
        
        result = ping1(dst="2001:db8:20::2", segs=["2001:db8:10::1"], hlim=1, return_pkt=True)
        tlv = new_srh_tlv(type=124, value='\x00\x01\x00\x00\x00\x01')
        
        ping_times = 3
        print("Send Large packets ...")
        for _ in range(ping_times):
            result = ping1(dst="2001:db8:20::2", segs=["2001:db8:10::1"], hlim=1, srh_tlvs=[tlv], return_pkt=True, data_len=800)
            if result:
                results.append(result)
        # echo reply
        self.assertTrue(len(results) > 0)
        print("Send packets: {}, Recieved packets: {}".format(ping_times, len(results)))

    def tearDown(self):
        """gRPC Client stop"""
        self.client.close_channel()
        self.client_thread.join(1)
