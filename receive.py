#!/usr/bin/env python3

from utils.InBandNetworkTelemetry import *
import prometheus_exporter

INTERFACE = 'eth0'


def _handle_telemetry_pkt(pkt):
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


def handle_pkt(pkt):
    if nodeCount in pkt:
        _handle_telemetry_pkt(pkt)

    if is_incoming_packet(pkt):  # showing only incoming packets
        pkt.show()


def is_incoming_packet(pkt):
    my_mac = get_if_hwaddr(INTERFACE)
    return pkt[Ether].dst == my_mac


def main():
    print("Start sniffing")
    bind_layers(IP, nodeCount, proto=253)

    #filter = "ip proto 253" telemetry packets are sent with IP protocol == 253
    #sniff(filter=filter, iface=INTERFACE, prn=lambda x: handle_pkt(x))

    sniff(iface=INTERFACE, prn=lambda x: handle_pkt(x))


if __name__ == '__main__':
    main()
