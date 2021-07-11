import sqlite3


class DBManager(object):
    """
    Using In-memory database.
    """
    def __init__(self, db_path=':memory:'):
        self.db_path = db_path
        self.cursor = None

        self._connect()
        self._init_db()

    def __del__(self):
        self.close_connection()

    def _connect(self):
        self.cursor = sqlite3.connect(self.db_path).cursor()

    def _init_db(self):
        self.cursor.execute("drop table if exists IPV4")

        sql = "CREATE TABLE IPV4" \
              "(ID INTEGER PRIMARY KEY AUTOINCREMENT, SwitchID VARCHAR(20), HostIP varchar(16), Port INTEGER, " \
              "MacAddress VARCHAR(17)) "

        self.cursor.execute(sql)
        self._populate_db()

    def _populate_db(self):
        sql = "INSERT INTO IPV4(SwitchID, HostIP, Port, MacAddress) VALUES (?,?,?,?)"
        data_tuple = [(1, '10.0.1.1', 1, "08:00:00:00:01:11"), (1, '10.0.2.2', 2, "08:00:00:00:02:22"),
                      (1, '10.0.3.3', 3, "08:00:00:00:03:00"), (1, '10.0.4.4', 4, "08:00:00:00:04:00")]
        self.cursor.executemany(sql, data_tuple)

    def insert(self, swid: int, ip: str, port: int, mac_addr: str):
        sql = "INSERT INTO IPV4 VALUES (?,?,?,?)"
        data_tuple = [(swid, ip, port, mac_addr)]
        self.cursor.executemany(sql, data_tuple)

    def dump(self) -> list:
        sql = "SELECT * FROM IPV4"
        result = self.cursor.execute(sql).fetchall()
        return result

    def get_ip(self, ip):
        pass

    def set_ip(self):
        pass

    def close_connection(self):
        self.cursor.close()


if __name__ == '__main__':
    db = DBManager()

    print(db.dump())
