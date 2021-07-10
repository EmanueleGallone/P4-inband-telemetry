#!/usr/bin/env python3

"""
Implementing a reactive Controller, using P4Runtime-Shell and PacketIO.
[WORK-IN-PROGRESS]
"""

import base64
import hashlib
import os
import socket
import argparse

import p4runtime_sh.shell as sh
from p4runtime_sh.shell import TableEntry
from google.protobuf.json_format import MessageToDict
from p4.v1.p4runtime_pb2 import StreamMessageResponse
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether

METADATA_ID_TO_HEADER = {  # as a reminder
    1: 'ingress_port',
    2: '_pad'
}

# TODO use a db
DB_IP_PORT = {
    "10.0.1.1": 1,
    "10.0.2.2": 2,
    "10.0.3.3": 3,
    "10.0.4.4": 4
}
DB_IP_MAC = {
    "10.0.1.1": "08:00:00:00:01:11",
    "10.0.2.2": "08:00:00:00:02:22",
    "10.0.3.3": "08:00:00:00:03:00",
    "10.0.4.4": "08:00:00:00:04:00"
}

# TODO use packet_out to deliver also the first packet


def _scapy_parse(packet: dict):
    """
    Trying to decode the packet payload sent by the data plane.
    """
    try:
        payload_base64 = packet['packet']['payload'].encode()

        # assuming it has a Ethernet layer. Scapy will handle the rest.
        packet = Ether(base64.decodebytes(payload_base64))

        if IP in packet:
            return packet

        return None  # actually not interested in packet not having IP layer
    except Exception as e:  # FIXME
        print(e)


def _parse_packet_metadata(packet: StreamMessageResponse) -> tuple:
    """
    This function retrieves the data from the packet_in header defined in P4
    """
    if packet is None:
        return ()
    packet = MessageToDict(packet)

    # Decoding Header
    ingress_port_base64 = packet['packet']['metadata'][0]['value'].encode()
    ingress_port = base64.decodebytes(ingress_port_base64)  # retrieving ingress_port; not used, yet

    # Decoding Payload
    packet = _scapy_parse(packet)

    return packet[IP].src, packet[IP].dst


def _hash(data):
    try:
        data = str(data).encode()
    except Exception as e:  # FIXME
        print(e)

    return hashlib.sha512(data).hexdigest()


class Controller(object):
    def __init__(self, p4rt_server_addr: str, device_id: int, p4info: str, p4json: str):

        self.p4rt_server = p4rt_server_addr
        self.shell = sh
        self.p4info = p4info
        self.p4json = p4json
        self.device_id = device_id
        self.election_id = (0, 0)  # BigInt(high, low)

        self.ipv4_table = "MyIngress.ipv4_lpm"
        self.ipv4_forward_action = "MyIngress.ipv4_forward"
        self.ipv4_table_entries = dict()

        self._connect_shell()

    def _connect_shell(self):
        self.election_id = (self.election_id[0], self.election_id[1] + 1)

        try:
            print("Connecting to {}".format(self.p4rt_server))
            self.shell.setup(
                device_id=self.device_id,
                grpc_addr=self.p4rt_server,
                election_id=self.election_id,
                config=self.shell.FwdPipeConfig(self.p4info, self.p4json)
            )
        except Exception as e:  # FIXME find the right exception
            raise e

    def _handle_packet_in(self, packet: StreamMessageResponse):
        if packet is None:
            return

        src_addr, dst_addr = _parse_packet_metadata(packet)

        mac_address = DB_IP_MAC[dst_addr]
        port = DB_IP_PORT[dst_addr]

        if self._check_db():
            self.insert_ipv4_entry(mac_address, dst_addr, port)

    def _check_db(self) -> bool:
        # FIXME implement the check function
        return True

    def _is_duplicated_rule(self, table_entry: TableEntry) -> bool:
        """
        Since the P4runtime overwrites entries already present inside the switch, I have
        to keep a record on all the previous matches and be sure to not add duplicated rules.
        Moreover, a simple comparison with table_entries does not work (I have yet to try to use str representation)
        so I'll use hashing.
        """
        te_hash = _hash(table_entry)

        if te_hash in self.ipv4_table_entries:  # avoiding duplicated ipv4 forwarding rules
            return True

    def _insert_ipv4_entry(self, table_entry: TableEntry):
        te_hash = _hash(table_entry)
        self.ipv4_table_entries[te_hash] = table_entry
        table_entry.insert()

    def insert_ipv4_entry(self, mac_addr: str, ip_address: str, port: int):
        te = TableEntry(self.ipv4_table)(action=self.ipv4_forward_action)
        te.match["hdr.ipv4.dstAddr"] = ip_address
        te.action["dstAddr"] = mac_addr
        te.action["port"] = str(port)

        if not self._is_duplicated_rule(te):
            print("Inserting rule: \n\tdst_addr:{}, port:{}".format(ip_address, port))
            self._insert_ipv4_entry(te)

    def sniff(self, timeout=None):
        """
        Applying the built-in handler defined within the controller
        """
        self.sniff2(lambda p: self._handle_packet_in(p), timeout=None)

    def sniff2(self, func=None, timeout=None):
        """
        func is the handler to be used when a new packet_in is detected
        if func is not provided, the method returns the packet_in
        """
        msg = None
        while True:
            msg = self.shell.client.get_stream_packet(type_="packet", timeout=timeout)
            if func is not None:
                func(msg)
            else:
                break
        return msg


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='build/basic.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='build/basic.json')
    parser.add_argument('--grpc-addr', help='grpc address to P4Runtime server (e.g. localhost:50051)',
                        type=str, required=False, default="localhost:50051")
    parser.add_argument('--device-id', help='P4Runtime server device id',
                        type=int, required=False, default=0)
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)

    controller = Controller(args.grpc_addr, args.device_id, args.p4info, args.bmv2_json)

    controller.sniff(timeout=None)
