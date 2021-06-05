import subprocess
import argparse
import sys
from topology_parser import TopologyParser

# TODO erase this and topology_parser.py. Used instead the program_switch_cli within run.py with files

class CustomConsole(object):
    def __init__(self, port):
        self.port = port
        self.output = None
        self._python_version = sys.version_info[0]

    def _console(self):
        if self._python_version == 3:
            return subprocess.Popen(['simple_switch_CLI', '--thrift-port', str(self.port)],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    encoding='utf-8'
                                    )
        elif self._python_version == 2:
            return subprocess.Popen(['simple_switch_CLI', '--thrift-port', str(self.port)],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE
                                    )

    def communicate(self, command):
        self.output = self._console().communicate(command)[0]
        return self._clean_output()

    def _clean_output(self):
        self.output = self.output.replace('Obtaining JSON from switch...', '')
        self.output = self.output.replace('Control utility for runtime P4 table manipulation', '')
        self.output = self.output.replace('RuntimeCmd:', '')
        self.output = self.output.replace('Done', '')
        return self.output.strip()


def autoset(json_file_path):
    topo_parser = TopologyParser(json_file_path)
    num_switches = topo_parser.get_num_switches()
    base_thrift_port = 9090

    for switch_id in range(num_switches):
        #  all the switches will be instantiated with an incremental thrift-port starting from 9090
        thrift_port = base_thrift_port + switch_id
        print(thrift_port)
        cmd = CustomConsole(thrift_port)
        cmd.communicate('table_set_default swtrace add_swtrace {}'.format(switch_id))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Switch Register Tool')
    parser.add_argument('-json', '--path-to-json-file',
                        help='parse the # of switches within the topology',
                        default='/pod-topo/topology.json',
                        required=True)

    args = parser.parse_args()
    autoset(args.path_to_json_file)
