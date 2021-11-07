from interceptors.db_auth import DBConnector
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import Column, Integer, String, ForeignKey


# generate tables and mapper()
db_auth = DBConnector()

Base = declarative_base()

class Packet(Base):

    #テーブルの名前
    __tablename__ = "packets"

    #テーブル内の属性
    id = Column('id', Integer, primary_key=True, autoincrement=True)
    ip = Column('fromIP', String(255)) #port番号を含む
    flags = Column('flags', String(255))
    length = Column('length', Integer, default=0)

    __table_args__ = {
        'mysql_engine': 'InnoDB',
        "mysql_charset": "utf8mb4",
        "mysql_row_format": "DYNAMIC"
    }

    def __init__(self, ip, flags, length):
        self.ip = ip
        self.flags = flags
        self.length = length


class Connection(Base):

    __tablename__ = "connections"

    id = Column('id', Integer, primary_key=True, autoincrement=True)
    ip = Column('IP', String(255), ForeignKey('users.ip', onupdate='CASCADE', ondelete='CASCADE')) #port番号を含まない
    packets = Column('packets', Integer)
    datasize = Column('datasize', Integer)
    login_result = Column('login_result', String(10))

    __table_args__ = {
        'mysql_engine': 'InnoDB',
        "mysql_charset": "utf8mb4",
        "mysql_row_format": "DYNAMIC"
    }

    def __init__(self, ip, packets, datasize, login_result):
        self.ip = ip
        self.packets = packets
        self.datasize = datasize
        self.login_result = login_result

class User(Base):

    __tablename__ = "users"
    id = Column('id', Integer, primary_key=True, autoincrement=True, )
    ip = Column('ip', String(15), unique=True) #port番号を含まない
    consecutive_failure = Column('consecutive_failure', Integer)

    __table_args__ = {
        'mysql_engine': 'InnoDB',
        "mysql_charset": "utf8mb4",
        "mysql_row_format": "DYNAMIC"
    }

    # カラム定義と同じインデントでrelationship(テーブルクラス名(テーブル名ではない))
    connection = relationship("Connection")

    def __init__(self, ip, consecutive_failure=0):
        self.ip = ip
        self.consecutive_failure = consecutive_failure

    def __repr__(self):
        return "<User('%s','%s', '%s')>" % (self.id, self.ip, self.consecutive_failure)


# urlを元にデータベースに接続
engine_url = db_auth.create_db_url()

#データベースに接続
engine = db_auth.connect_db(engine_url=engine_url)

#テーブルをDBに作成
Base.metadata.create_all(engine)

# テーブルをDBに作成
session = db_auth.make_session(engine)


