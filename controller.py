#!/usr/bin/env python3

# Copyright 2021 EmanueleGallone
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""
Implementing a reactive Controller, using P4Runtime-Shell and PacketIO.
[WORK-IN-PROGRESS]
"""

import base64
import hashlib
import os
import argparse
import logging
import sys

import p4runtime_sh.shell as sh
from p4runtime_sh.shell import TableEntry
from google.protobuf.json_format import MessageToDict
from p4.v1.p4runtime_pb2 import StreamMessageResponse
from p4runtime_sh.utils import UserError
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.packet import Packet

from utils.database.SQLiteImpl import SQLiteImpl

FORMAT = '%(asctime)-15s [%(levelname)s] %(message)s'
logging.basicConfig(level=logging.DEBUG, format=FORMAT, filename='logs/controller.log')

# As a reminder:
# METADATA_ID_TO_HEADER = {
#     1: 'ingress_port',
#     2: '_pad'
# }
#
# DB_IP_PORT = {
#     "10.0.1.1": 1,
#     "10.0.2.2": 2,
#     "10.0.3.3": 3,
#     "10.0.4.4": 4
# }
# DB_IP_MAC = {
#     "10.0.1.1": "08:00:00:00:01:11",
#     "10.0.2.2": "08:00:00:00:02:22",
#     "10.0.3.3": "08:00:00:00:03:00",
#     "10.0.4.4": "08:00:00:00:04:00"
# }


def _scapy_parse(packet: dict) -> Packet:
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
        logging.debug(e)


def _parse_packet(packet: StreamMessageResponse) -> Packet:
    """
    This function retrieves the data from the packet_in header defined in P4 and its payload.
    """
    if packet is None:
        raise TypeError("Packet cannot be None!")

    packet = MessageToDict(packet)

    # Decoding Header
    ingress_port_base64 = packet['packet']['metadata'][0]['value'].encode()
    ingress_port = base64.decodebytes(ingress_port_base64)  # retrieving ingress_port; not used, yet

    # Decoding Payload
    packet = _scapy_parse(packet)

    return packet


def _hash(data) -> str:
    _result = ""
    try:
        _data = str(data).encode()
        _result = hashlib.sha512(_data).hexdigest()
    except Exception as e:  # FIXME
        logging.debug(e)

    return _result


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

        self.local_breakout_table = "MyIngress.ipv4_local_breakout"
        self.local_breakout_action = "MyIngress.local_breakout"

        self.table_entries = dict()

        self.db_manager = SQLiteImpl()

        self._connect_shell()

    def _connect_shell(self):
        self.election_id = (self.election_id[0], self.election_id[1] + 1)

        try:
            logging.info("Connecting to {}".format(self.p4rt_server))
            self.shell.setup(
                device_id=self.device_id,
                grpc_addr=self.p4rt_server,
                election_id=self.election_id,
                config=self.shell.FwdPipeConfig(self.p4info, self.p4json)
            )
        except Exception as e:  # FIXME find the right exception
            raise e

    def _handle_packet_in(self, packet: StreamMessageResponse) -> None:
        if packet is None:
            return

        scapy_packet = _parse_packet(packet)  # TODO check if parsed_packet is None

        src_addr, dst_addr = scapy_packet[IP].src, scapy_packet[IP].dst

        mac_address = self.db_manager.get_mac_from_ip(dst_addr)
        port = self.db_manager.get_port_from_ip(dst_addr)

        breakout_dst_addr = self.db_manager.get_breakout_address(src_addr, dst_addr)

        if breakout_dst_addr is not None:  # setup breakout
            self.insert_ipv4_local_breakout_entry(src_addr, dst_addr, breakout_dst_addr)

        if self._check_db():
            # TODO if no rule is detected, set ipv4_entry to drop packets

            self.insert_ipv4_entry(mac_address, dst_addr, port)  # setup connectivity

            # done inserting new entry, now send the received packet_in as a packet_out
            self._send_packet_out(scapy_packet, port)

    def _check_db(self) -> bool:
        # FIXME implement the check function
        return True

    def _is_duplicated_rule(self, table_entry: TableEntry) -> bool:
        """
        Since the P4runtime overwrites entries already present inside the switch, I have
        to keep a record on all the previous entries and be sure to not add duplicated rules.
        Moreover, a simple comparison with table_entries does not work (I have yet to try to use str representation)
        so I'll use hashing.
        """
        te_hash = _hash(table_entry)
        if te_hash in self.table_entries:  # avoiding duplicated ipv4 forwarding rules
            return True

    def _send_packet_out(self, packet: Packet, port) -> None:
        """
        This method will send a Packet-out back to the data-plane.
        """
        try:
            p = self.shell.PacketOut(bytes(packet), egress_port=str(port))
            p.send()
            logging.debug("Sending packet out: egress_port {}".format(port))
        except UserError as e:
            logging.debug(e)
        return

    def _insert_ipv4_entry(self, table_entry: TableEntry) -> None:
        te_hash = _hash(table_entry)
        self.table_entries[te_hash] = table_entry
        table_entry.insert()

    def insert_ipv4_entry(self, mac_addr: str, ip_address: str, port: int) -> None:
        te = TableEntry(self.ipv4_table)(action=self.ipv4_forward_action)
        te.match["hdr.ipv4.dstAddr"] = ip_address
        te.action["dstAddr"] = mac_addr
        te.action["port"] = str(port)

        if not self._is_duplicated_rule(te):
            logging.info("Inserting IPV4 forwarding rule: dst_addr:{}, port:{}".format(ip_address, port))
            self._insert_ipv4_entry(te)

    def insert_ipv4_local_breakout_entry(self, src_ip_address: str, dst_ip_address: str, breakout_ip_address: str):
        te = TableEntry(self.local_breakout_table)(action=self.local_breakout_action)
        te.match["hdr.ipv4.srcAddr"] = src_ip_address
        te.match["hdr.ipv4.dstAddr"] = dst_ip_address
        te.action["dstAddr"] = breakout_ip_address

        if not self._is_duplicated_rule(te):
            logging.info("Inserting IPV4 Breakout rule: original_dst_addr:{}, breakout_dst_addr:{}".format(dst_ip_address, breakout_ip_address))
            self._insert_ipv4_local_breakout_entry(te)

    def _insert_ipv4_local_breakout_entry(self, table_entry: TableEntry):
        te_hash = _hash(table_entry)
        self.table_entries[te_hash] = table_entry
        table_entry.insert()

    def start(self, timeout=None) -> None:
        """
        Applying the built-in handler defined within the controller
        """
        self.sniff(lambda p: self._handle_packet_in(p), timeout=None)

    def sniff(self, func=None, timeout=None):
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
                        default='build/main.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='build/main.json')
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

    try:
        print("Starting Controller: connecting to {}".format(args.grpc_addr))
        controller.start(timeout=None)
    except KeyboardInterrupt:
        print("\nCTRL-C Detected: Exiting")
        sys.exit(0)
