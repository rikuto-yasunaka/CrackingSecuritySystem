from sqlalchemy import create_engine
from config import base_setting
from sqlalchemy.orm import sessionmaker

class DBConnector(object):

    def __init__(self, ):
        self._driver = "pymysql"
        self._username = base_setting.DB_USER
        self._password = base_setting.DB_PASSWORD
        self._host = base_setting.DB_HOST
        self._port = base_setting.DB_PORT
        self._database = base_setting.DB_NAME
        self._charset_type = base_setting.DB_CHARSET_TYPE
        self._dialect = "mysql"

    def create_db_url(self):
        engine_url = \
            f"{self._dialect}+{self._driver}://{self._username}:{self._password}@{self._host}" \
            f":{self._port}/{self._database}?charset={self._charset_type}"
        return engine_url

    def connect_db(self, engine_url):
        # urlを元にデータベースに接続
        engine = create_engine(engine_url)
        return engine

    def make_session(self, engine):
        # セッションを作るクラスを作成
        SessionClass = sessionmaker(engine)
        session = SessionClass()
        return session