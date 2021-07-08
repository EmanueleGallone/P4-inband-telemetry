#!/usr/bin/env python3

import sys
import p4runtime_sh.shell as sh


def controller():
    p4rt_server_addr = 'localhost:50051'

    print("Starting controller; connecting to {}".format(p4rt_server_addr))

    sh.setup(
        device_id=0,
        grpc_addr=p4rt_server_addr,
        election_id=(0, 2),  # (high, low)
        config=sh.FwdPipeConfig('build/basic.p4.p4info.txt', 'build/basic.json')
    )

    try:
        packet_in = sh.PacketIn()
        packets = packet_in.sniff(lambda packet: print(packet), timeout=5)

    except KeyboardInterrupt as e:
        pass

    finally:
        sys.exit()


if __name__ == '__main__':
    controller()
