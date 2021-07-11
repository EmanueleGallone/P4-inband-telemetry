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
