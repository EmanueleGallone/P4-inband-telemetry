from prometheus_client import start_http_server, Summary, Gauge
import random
import time

#TODO choose which metrics to collect

# class Exporter(object):
#     def __init__(self, fields):
#         self.fields = fields
#         self.server_running = False

# REQUEST_TIME = Summary('request_processing_seconds', 'Time spent processing request')
# @REQUEST_TIME.time()
# def process_request(t):
#     time.sleep(t)

QUEUE_LENGTH = Gauge('queue_length', 'number of packets queued')


def process_INT(fields: dict) -> None:
    # for key, value in fields.items():
    #     pass
    pass


def run_server(port=9000) -> None:
    start_http_server(port=port, addr='localhost')
    print("start serving on port {}".format(port))


if __name__ == '__main__':
    run_server()
    # while True:
    #     process_request(random.random())
