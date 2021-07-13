#!/usr/bin/env python3

import argparse
from time import sleep
from utils.InBandNetworkTelemetry import *


class nodeCount(Packet):
    name = "nodeCount"
    fields_desc = [ShortField("count", 0),
                   PacketListField("INT", [], InBandNetworkTelemetry, count_from=lambda pkt: (pkt.count * 1))]


def main(args):
    addr = args.destinationIP
    iface = args.interface
    rate = args.rate  # req/s -> 0.5 sleep time

    bind_layers(IP, nodeCount, proto=253)
    pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / IP(
        dst=addr, proto=253) / nodeCount(count=0, INT=[])

    while True:
        sendp(pkt, iface=iface)
        pkt.show2()
        sleep(rate)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='In-Band Telemetry packet sender')
    parser.add_argument('-d', '--destinationIP',
                        help='set the destinationIP where to send the packets',
                        default='10.0.4.4', type=str),
    parser.add_argument('-i', '--interface', help='set the Interface', default='eth0', type=str)
    parser.add_argument('-r', '--rate', help='set the INT packets\' rate', default=0.5, type=int)

    args = parser.parse_args()

    main(args)
