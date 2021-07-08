#!/usr/bin/env python3

import base64
import sys
import socket
import p4runtime_sh.shell as sh
from google.protobuf.json_format import MessageToDict

METADATA_ID_TO_HEADER = {
    1: 'src_address',
    2: 'dst_address',
    3: 'ingress_port',
    4: '_pad'
}


def _packets_to_list(packets: iter) -> list:
    """
    Using the MessageToDict method provided by the google.protobuf library
    to convert the output received by the p4runtime-shell to a list of python dictionaries
    """
    return [MessageToDict(packet) for packet in packets]


def insert_entry(shell: sh):
    pass


def handle_packetin_metadata(packets: iter):
    packets = _packets_to_list(packets)

    for packet in packets:
        src_address_base64 = packet['packet']['metadata'][0]['value'].encode()
        dst_address_base64 = packet['packet']['metadata'][1]['value'].encode()
        src_addr = socket.inet_ntoa(base64.decodebytes(src_address_base64))
        dst_addr = socket.inet_ntoa(base64.decodebytes(dst_address_base64))

        print("packet_in : \n\tsrc_addr: {}, dst_addr: {}".format(src_addr, dst_addr))
        # TODO if dst_addr not in ipv4 table, check if host should be added to ipv4_table


def controller(p4rt_server_addr='localhost', p4rt_server_port='50051'):
    p4rt_server = "{}:{}".format(p4rt_server_addr, p4rt_server_port)

    print("Controller connecting to {}".format(p4rt_server))

    sh.setup(
        device_id=0,
        grpc_addr=p4rt_server,
        election_id=(0, 2),  # (high, low)
        config=sh.FwdPipeConfig('build/basic.p4.p4info.txt', 'build/basic.json')
    )

    try:
        packets = sh.PacketIn().sniff(timeout=5)
        handle_packetin_metadata(packets)

    except KeyboardInterrupt:
        sys.exit(0)

    except Exception as e:
        print(e)

    # finally:
    #     sys.exit()


if __name__ == '__main__':
    controller()
