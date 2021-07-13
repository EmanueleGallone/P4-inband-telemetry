#!/usr/bin/env python3

from utils.InBandNetworkTelemetry import *
import prometheus_exporter


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

    pkt.show()
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
