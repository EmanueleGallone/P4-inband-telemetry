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
from abc import ABC, abstractmethod


class DBManager(ABC):
    """
    Defining a common API for a set of subclasses that can implement different database technologies.
    """
    def __init__(self, db_path=None):
        super().__init__()
        self.db_path = db_path

        self.ipv4_table = "IPV4"
        self.local_breakout_table = "IPV4LocalBreakout"

    def __del__(self):
        self.close_connection()

    @abstractmethod
    def _connect(self):
        pass

    @abstractmethod
    def _init_db(self):
        pass

    @abstractmethod
    def _commit(self):
        pass

    @abstractmethod
    def _populate_db(self):
        pass

    @abstractmethod
    def insert(self, swid: int, ip: str, port: int, mac_addr: str):
        pass

    @abstractmethod
    def dump(self) -> list:
        pass

    @abstractmethod
    def get_mac_from_ip(self, ip: str):
        pass

    @abstractmethod
    def get_port_from_ip(self, ip: str):
        pass

    @abstractmethod
    def get_breakout_address(self, src_ip: str, dst_ip: str):
        pass

    @abstractmethod
    def close_connection(self):
        pass


if __name__ == '__main__':
    db = DBManager()

    print(db.dump())
