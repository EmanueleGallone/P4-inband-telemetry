from prometheus_client import start_http_server, Summary
import random
import time

#TODO choose which metrics to collect

REQUEST_TIME = Summary('request_processing_seconds', 'Time spent processing request')


@REQUEST_TIME.time()
def process_request(t):
    time.sleep(t)


if __name__ == '__main__':
    port = 9000
    start_http_server(port)
    print("start serving on port {}".format(port))

    while True:
        process_request(random.random())
