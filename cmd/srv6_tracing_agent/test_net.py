from ipnet import IPNetwork, CLIX
import ipnet.examples.srv6.simple_srv6_6 as srv6net


def setup() -> IPNetwork:
    net = srv6net.setup()
    # net["r1"].cmdPrint("cd srv6ptf_nfagent/;./start_agent_standalone.sh r1.log 1 &")
#     net["r4"].cmdPrint("cd srv6ptf_nfagent/;./start_agent_standalone.sh r4.log 4 &")
    net.add_mgmt_network(controller_name="c1")
    net.start()

    print("***** r1 IPv6 Route *****")
    net["r1"].cmdPrint("ip -6 route")

    print("***** r4 IPv6 Route *****")
    net["r4"].cmdPrint("ip -6 route")

    return net


if __name__ == "__main__":
    net = setup()
    CLIX(net)
    net.stop()
