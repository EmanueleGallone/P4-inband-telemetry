import argparse
import json
import os.path


class TopologyParser(object):
    """
    returns the # of switches within the provided topology.json
    """

    def __init__(self, json_path=None):
        self.json_path = json_path
        self.json = None
        self.num_switches = 0

        self._load_json()
        self._parse_num_switches()

    def _load_json(self):
        if os.path.isfile(self.json_path) is False:
            raise FileNotFoundError

        with open(self.json_path, mode='r') as file:
            self.json = json.load(file)

    def _parse_num_switches(self):
        self.num_switches = len(self.json['switches'].items())

    def get_num_switches(self):
        return self.num_switches


def main(json_path):
    parser = TopologyParser(json_path)
    print(parser.get_num_switches())


if __name__ == '__main__':
    argparser = argparse.ArgumentParser('parse mininet topology json to discover # of switches')
    argparser.add_argument('-json', '--path-to-json-file',
                           help='parse the # of switches within the topology',
                           default='/pod-topo/topology.json')

    main(argparser.parse_args().path_to_json_file)
