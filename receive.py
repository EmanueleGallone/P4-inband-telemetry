#!/usr/bin/env python3

from scapy.all import Packet, bind_layers, BitField, ShortField, PacketListField, Ether, IP, UDP, sniff
import prometheus_client

import prometheus_exporter


class InBandNetworkTelemetry(Packet):
    fields_desc = [BitField("switchID_t", 0, 31),
                   BitField("ingress_port", 0, 9),
                   BitField("egress_port", 0, 9),
                   BitField("egress_spec", 0, 9),
                   BitField("ingress_global_timestamp", 0, 48),
                   BitField("egress_global_timestamp", 0, 48),
                   BitField("enq_timestamp", 0, 32),
                   BitField("enq_qdepth", 0, 19),
                   BitField("deq_timedelta", 0, 32),
                   BitField("deq_qdepth", 0, 19)
                   ]
    """any thing after this packet is extracted is padding"""

    def extract_padding(self, p):
        return "", p


class nodeCount(Packet):
    name = "nodeCount"
    fields_desc = [ShortField("count", 0),
                   PacketListField("INT", [], InBandNetworkTelemetry, count_from=lambda pkt: (pkt.count * 1))]


def handle_pkt(pkt):
    count = 0
    fields = {}
    while count < pkt[nodeCount].count:
        p = pkt[nodeCount].INT[count]
        fields['switchID_t'] = p.switchID_t
        fields['ingress_port'] = p.ingress_port
        fields['egress_port'] = p.egress_port
        fields['egress_spec'] = p.egress_spec
        fields['ingress_global_timestamp'] = p.ingress_global_timestamp
        fields['egress_global_timestamp'] = p.egress_global_timestamp
        fields['enq_timestamp'] = p.enq_timestamp
        fields['enq_qdepth'] = p.enq_qdepth
        fields['deq_timedelta'] = p.deq_timedelta
        fields['deq_qdepth'] = p.deq_qdepth

        count += 1

        prometheus_exporter.process_INT(fields)

    # print(pkt[nodeCount].getfield())
    # string = pkt[nodeCount].show(dump=True)
    # print("packet: \n %s \n %s".format(string, ))


def main():
    iface = 'eth0'
    print("Start sniffing")
    bind_layers(IP, nodeCount, proto=253)
    sniff(filter="ip proto 253", iface=iface, prn=lambda x: handle_pkt(x))


if __name__ == '__main__':
    main()
