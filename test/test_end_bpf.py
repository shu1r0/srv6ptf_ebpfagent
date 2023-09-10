from unittest import TestCase, main
from logging import getLogger
from scapy.all import *
from json import dumps

from nfagent.collector_grpc.collector_client import PacketCollectorClient

from srv6_ping.ping import ping1, new_srh_tlv


class TestEndBPF(TestCase):

    def setUp(self):
        self.client = PacketCollectorClient(ip="192.168.10.2", port="31000", node_id=1, node_id_length=16,
                                            logger=getLogger(__name__),
                                            counter_length=32,
                                            enable_stats=True)
        self.client.establish_channel()

        def notify_packet_handler(data):
            print("***** Received from agent *****")
            print(data)

        def notify_packetid_handler(data):
            print("***** Received from agent *****")
            print(data)

        def client_start():
            loop = self.client.event_loop
            loop.run_until_complete(
                self.client.notify_packet_info_coro(notify_packet_handler, notify_packetid_handler, True))

        self.client_thread = threading.Thread(target=client_start)
        self.client_thread.start()
    
    def test_srv6_ping(self):
        results = []
        
        # Send SRv6 packet
        ping_times = 3
        print("Send packets ...")
        for _ in range(ping_times):
            result = ping1(dst="2001:db8:20::1", segs=["2001:db8:10::3"], hlim=1, return_pkt=True)
            if result:
                results.append(result)
        self.assertTrue(len(results) > 0)
        if len(results) > 0:
            for result in results:
                self.assertEqual("TimeExceeded", result["msg"])
                # check return_pkt
                self.assertTrue(result["sent_pkt"][IPv6].src == result["recv_pkt"][IPv6].dst)
                self.assertTrue(IPv6ExtHdrSegmentRoutingTLV in result["recv_pkt"])
            # print("Received packets: {}".format(results))
        print("Send packets: {}, Recieved packets: {}".format(ping_times, len(results)))
        
        # Send SRv6 packet with PktId TLV
        ping_times = 3
        print("Send packetid")
        tlv = new_srh_tlv(type=124, value='\x00\x01\x00\x00\x00\x01')
        for _ in range(ping_times):
            result = ping1(dst="2001:db8:20::1", segs=["2001:db8:10::3"], hlim=1, srh_tlvs=[tlv], return_pkt=True)
            if result:
                results.append(result)
        self.assertTrue(len(results) > 0)
        if len(results) > 0:
            for result in results:
                self.assertEqual("TimeExceeded", result["msg"])
                self.assertTrue(IPv6ExtHdrSegmentRoutingTLV in result["recv_pkt"])
        print("Send packets: {}, Recieved packets: {}".format(ping_times, len(results)))
        
    # def test_xmit_readid_ping(self):
    #     results = []
    #     print("Send packets ...")
    #     result = ping1(dst="2001:db8:10::4", hlim=1, return_pkt=True)
    #     print(result)
    #     for _ in range(3):
    #         result = ping1(dst="2001:db8:20::1", segs=["2001:db8:10::4"], hlim=1, return_pkt=True)
    #         if result:
    #             results.append(result)
        
    #     # echo reply
    #     self.assertTrue(len(results) > 0)
    #     print("Received packets: {}".format(results))
    #     if len(results) > 0:
    #         for result in results:
    #             self.assertEqual("TimeExceeded", result["msg"])
    #             # check return_pkt
    #             self.assertTrue(result["sent_pkt"][IPv6].src == result["recv_pkt"][IPv6].dst)
    #             self.assertTrue(IPv6ExtHdrSegmentRoutingTLV in result["recv_pkt"])
        
    #     print("send packetid")
    #     tlv = new_srh_tlv(type=124, value='\x00\x01\x00\x00\x00\x01')
    #     result = ping1(dst="2001:db8:20::1", segs=["2001:db8:10::4"], hlim=1, srh_tlvs=[tlv], return_pkt=True)
    #     self.assertEqual("TimeExceeded", result["msg"])
    #     result["recv_pkt"].show()
        
    #     time.sleep(1)
        
    # def test_in_readid_ping(self):
    #     results = []
    #     print("Send packets ...")
    #     result = ping1(dst="2001:db8:10::5", hlim=1, return_pkt=True)
    #     print(result)
    #     for _ in range(3):
    #         result = ping1(dst="2001:db8:20::1", segs=["2001:db8:10::5"], hlim=1, return_pkt=True)
    #         if result:
    #             results.append(result)
        
    #     # echo reply
    #     self.assertTrue(len(results) > 0)
    #     print("Received packets: {}".format(results))
    #     if len(results) > 0:
    #         for result in results:
    #             self.assertEqual("TimeExceeded", result["msg"])
    #             # check return_pkt
    #             self.assertTrue(result["sent_pkt"][IPv6].src == result["recv_pkt"][IPv6].dst)
    #             self.assertTrue(IPv6ExtHdrSegmentRoutingTLV in result["recv_pkt"])
        
    #     print("send packetid")
    #     tlv = new_srh_tlv(type=124, value='\x00\x01\x00\x00\x00\x01')
    #     result = ping1(dst="2001:db8:20::1", segs=["2001:db8:10::5"], hlim=1, srh_tlvs=[tlv], return_pkt=True)
    #     self.assertEqual("TimeExceeded", result["msg"])
    #     result["recv_pkt"].show()
        
    #     time.sleep(1)
        
    # def test_out_readid_ping(self):
    #     results = []
    #     print("Send packets ...")
    #     result = ping1(dst="2001:db8:10::6", hlim=1, return_pkt=True)
    #     print(result)
    #     for _ in range(3):
    #         result = ping1(dst="2001:db8:20::1", segs=["2001:db8:10::6"], hlim=1, return_pkt=True)
    #         if result:
    #             results.append(result)
        
    #     # echo reply
    #     self.assertTrue(len(results) > 0)
    #     print("Received packets: {}".format(results))
    #     if len(results) > 0:
    #         for result in results:
    #             self.assertEqual("TimeExceeded", result["msg"])
    #             # check return_pkt
    #             self.assertTrue(result["sent_pkt"][IPv6].src == result["recv_pkt"][IPv6].dst)
    #             self.assertTrue(IPv6ExtHdrSegmentRoutingTLV in result["recv_pkt"])
        
    #     print("send packetid")
    #     tlv = new_srh_tlv(type=124, value='\x00\x01\x00\x00\x00\x01')
    #     result = ping1(dst="2001:db8:20::1", segs=["2001:db8:10::6"], hlim=1, srh_tlvs=[tlv], return_pkt=True)
    #     self.assertEqual("TimeExceeded", result["msg"])
    #     result["recv_pkt"].show()
        
    #     time.sleep(1)

    def tearDown(self):
        self.client.close_channel()
        self.client_thread.join(1)
