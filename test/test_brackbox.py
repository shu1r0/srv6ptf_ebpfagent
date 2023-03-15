from unittest import TestCase, main
from scapy.all import *
from json import dumps


from srv6_ping.ping import ping1, new_srh_tlv


class TestSPacket(TestCase):
    
    def test_srv6_ping(self):
        results = []
        print("Send packets ...")
        for _ in range(3):
            result = ping1(dst="2001:db8:20::1", segs=["2001:db8:10::2"], hlim=1, return_pkt=True)
            if result:
                results.append(result)
        
        # echo reply
        self.assertTrue(len(results) > 0)
        print("Received packets: {}".format(results))
        if len(results) > 0:
            for result in results:
                self.assertEqual("TimeExceeded", result["msg"])
                # check return_pkt
                self.assertTrue(result["sent_pkt"][IPv6].src == result["recv_pkt"][IPv6].dst)
                self.assertTrue(IPv6ExtHdrSegmentRoutingTLV in result["recv_pkt"])