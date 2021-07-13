#!/usr/bin/env python3

from scapy.all import Packet, bind_layers, BitField, ShortField, PacketListField
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sendp, sniff
from scapy.arch import get_if_hwaddr


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