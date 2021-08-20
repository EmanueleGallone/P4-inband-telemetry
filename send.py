#!/usr/bin/env python3

import argparse
from time import sleep
from utils.InBandNetworkTelemetry import *


def main(args):
    addr = args.destinationIP
    iface = args.interface
    rate = args.rate

    bind_layers(IP, nodeCount, proto=253)
    int_pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / IP(
        dst=addr, proto=253) / nodeCount(count=0, INT=[])

    gtp_packet = Ether(
        src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / IP(
        dst=addr) / UDP() / GTP_U_Header() / IP(
        src="10.0.1.1", dst="10.0.4.4") / ICMP()

    while True:
        #sendp(gtp_packet, iface=iface)
        #print("GTP packet sent")

        sendp(int_pkt, iface=iface)
        #int_pkt.show2()
        print("INT packet sent")
        sleep(rate)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='In-Band Telemetry packet sender')
    parser.add_argument('-d', '--destinationIP',
                        help='set the destinationIP where to send the packets',
                        default='10.0.4.4', type=str),
    parser.add_argument('-i', '--interface', help='set the Interface', default='eth0', type=str)
    parser.add_argument('-r', '--rate', help='set the packets\' rate', default=1, type=int)

    args = parser.parse_args()

    main(args)
