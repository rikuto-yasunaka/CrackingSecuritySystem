import configparser
import os
import errno
import subprocess


config_txt = configparser.ConfigParser()
config_txt_path = 'config/config.init'

#pathにファイルが無かった時のエラー
if not os.path.exists(config_txt_path):
    raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), config_txt)

#グローバルIPアドレスを取得
cmd = "curl inet-ip.info"
global_ip = (subprocess.check_output(cmd.split())).decode(encoding='utf-8')
global_ip = global_ip.rstrip("\n")
print('your IP Address', global_ip)

#config.initファイルを読み込む
config_txt.read(config_txt_path, encoding='UTF-8')

#辞書型で取り出す
read_ssh = config_txt['SSH']
read_db = config_txt['DB']

#SSH接続用の認証情報とコマンド
HOST = read_ssh['host']
SSH_USER = read_ssh['user']
SSH_PASSWORD = read_ssh['password']
PORT = read_ssh['port']

#データベース用の認証情報
DB_USER = read_db['user']
DB_PASSWORD = read_db['password']
DB_NAME = read_db['dbname']
DB_HOST = read_db['host']
DB_PORT = read_db['port']
DB_CHARSET_TYPE = read_db['charset_type']
