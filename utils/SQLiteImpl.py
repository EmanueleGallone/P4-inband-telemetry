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

import sqlite3
from utils.db_manager import DBManager


class SQLiteImpl(DBManager):

    def __init__(self, db_path=":memory:"):
        super().__init__(db_path)

        self._connection = None
        self.cursor = None

        self._connect()
        self._init_db()

    def _connect(self):
        self._connection = sqlite3.connect(self.db_path)
        self.cursor = self._connection.cursor()

    def _init_db(self):
        """
        This method should be used in case of an in-memory database. At each start the db is initialized
        and then then populated

        Returns: None

        """
        self.cursor.execute("drop table if exists {}".format(self.ipv4_table))
        self.cursor.execute("drop table if exists {}".format(self.local_breakout_table))

        ipv4_sql = "CREATE TABLE {}" \
                   " (ID INTEGER PRIMARY KEY AUTOINCREMENT," \
                   " SwitchID VARCHAR(20) NOT NULL," \
                   " IPV4HostIP VARCHAR(16) NOT NULL," \
                   " Port INTEGER NOT NULL, " \
                   " MacAddress VARCHAR(17) NOT NULL" \
                   ")".format(self.ipv4_table)

        self.cursor.execute(ipv4_sql)

        local_breakout_sql = "CREATE TABLE {}" \
                             " (ID INTEGER PRIMARY KEY AUTOINCREMENT," \
                             " IPV4SrcAddress VARCHAR(16) NOT NULL ," \
                             " IPV4DstAddress VARCHAR(16) ," \
                             " DstPort INTEGER ," \
                             " BreakoutIPV4DstAddress VARCHAR(16) NOT NULL," \
                             " BreakoutPort INTEGER " \
                             ")".format(self.local_breakout_table)

        self.cursor.execute(local_breakout_sql)

        self._populate_db()

    def _commit(self):
        self._connection.commit()

    def insert(self, swid: int, ip: str, port: int, mac_addr: str):
        raise NotImplementedError
        # sql = "INSERT INTO IPV4 VALUES (?,?,?,?)"
        # data_tuple = [(swid, ip, port, mac_addr)]
        # self.cursor.executemany(sql, data_tuple)
        # self._commit()

    def _populate_db(self):
        sql = "INSERT INTO {}(SwitchID, IPV4HostIP, Port, MacAddress) VALUES (?,?,?,?)".format(self.ipv4_table)

        data_tuple = [(1, '10.0.1.1', 1, "08:00:00:00:01:11"), (1, '10.0.2.2', 2, "08:00:00:00:02:22"),
                      (1, '10.0.3.3', 3, "08:00:00:00:03:00"), (1, '10.0.4.4', 4, "08:00:00:00:04:00")]

        self.cursor.executemany(sql, data_tuple)
        self._commit()

        sql = "INSERT INTO {}(" \
              " IPV4SrcAddress," \
              " IPV4DstAddress," \
              " DstPort," \
              " BreakoutIPV4DstAddress," \
              " BreakoutPort" \
              ") VALUES (?,?,?,?,?)".format(self.local_breakout_table)

        data_tuple = [('10.0.1.1', "10.0.2.2", None, '10.0.4.4', None)]

        self.cursor.executemany(sql, data_tuple)
        self._commit()

    def dump(self) -> list:
        result = []

        sql = "SELECT * FROM {}".format(self.ipv4_table)
        result.append(self.cursor.execute(sql).fetchall())

        sql = "SELECT * FROM {}".format(self.local_breakout_table)
        result.append(self.cursor.execute(sql).fetchall())

        return result

    def get_mac_from_ip(self, ip: str):
        sql = "SELECT MacAddress FROM {} WHERE IPV4HostIP=?".format(self.ipv4_table)
        result = self.cursor.execute(sql, (ip,)).fetchone()

        if result is not None:
            return result[0]

        return None

    def get_port_from_ip(self, ip: str):
        sql = "SELECT Port FROM {} WHERE IPV4HostIP=?".format(self.ipv4_table)
        result = self.cursor.execute(sql, (ip,)).fetchone()

        if result is not None:
            return result[0]

        return None

    def get_breakout_address(self, src_ip: str, dst_ip: str):
        sql = "SELECT BreakoutIPV4DstAddress FROM {}" \
              " WHERE IPV4SrcAddress=? " \
              " AND IPV4DstAddress=?".format(self.local_breakout_table)

        result = self.cursor.execute(sql, (src_ip, dst_ip)).fetchone()
        if result is not None:
            return result[0]

        return None

    def close_connection(self):
        self._connection.close()


if __name__ == '__main__':
    db = SQLiteImpl()

    print(db.dump())
