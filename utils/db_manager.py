import sqlite3


class DBManager(object):
    def __init__(self, db_path='test.db'):
        self.db_path = db_path
        self.cursor = sqlite3.connect(self.db_path).cursor()

        self._init_db()

    def __del__(self):
        self.cursor.close()

    def _init_db(self):
        sql = "CREATE TABLE IPV4 IF NOT EXISTS " \
              "(ID INTEGER PRIMARY KEY AUTOINCREMENT, SwitchID VARCHAR(20), HostIP varchar(16), Port INTEGER)"
        self.cursor.execute(sql)

    def insert(self):
        sql = "INSERT INTO IPV4 VALUES (?,?,?)"
        data_tuple = [(1, '10.0.1.1', 0)]
        self.cursor.executemany(sql, data_tuple)

    def _dump(self):
        sql = "SELECT * FROM IPV4"
        self.cursor.execute(sql)

    def get_ip(self, ip):
        pass

    def set_ip(self):
        pass


if __name__ == '__main__':
    db = DBManager()
