import paramiko
import settings
from config import base_setting
import time
import re

class SSHConnector(object):

    __hostName = ''
    __userName = ''
    __password = ''
    __port = ''

    def __init__(self):
        self.__key_path = settings.KEY_ROOT
        self.__hostName = base_setting.HOST
        self.__userName = base_setting.SSH_USER
        self.__password = base_setting.SSH_PASSWORD
        self.__port = base_setting.PORT
        self.client = self._make_client()
        self.channel = self._make_channel()

    def __del__(self):
        pass

    def _make_client(self):
        try:
            # sshclientオブジェクトの作成
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            # 秘密鍵ファイルをrsa鍵オブジェクトに変換
            pkey = paramiko.RSAKey.from_private_key_file(self.__key_path)
            # ssh接続を行う
            client.connect(hostname=self.__hostName, username=self.__userName, password=self.__password, pkey=pkey)
            return client

        except paramiko.BadHostKeyException:
            print("the server’s host key could not be verified")
            return None

        except paramiko.AuthenticationException:
            print("authentication failed")
            return None

        except paramiko.SSHException:
            print("there was any other error connecting or establishing an SSH session")
            return None

        except paramiko.socket.error:
            print("a socket error occurred while connecting")
            return None

    def _make_channel(self):
        channel = self.client.get_transport().open_session()
        return channel

    #tcpdumpコマンドを実行し、queueにタスクを入れる
    def exec_command(self, queue):

        # 実行するコマンド
        command = 'sudo tcpdump host not {} and -nn port 22 -i eth0 -tttt;'.format(base_setting.global_ip)

        #channelの作成
        channel = self.client.get_transport().open_session(timeout=100)

        try:
            #invoke_shellを呼び出す前のメソッド
            channel.get_pty()
            #バックグラウンド処理開始
            channel.invoke_shell()
            time.sleep(3)
            #コマンドの記述
            channel.send(command + "\n")
            time.sleep(1)
            #パスワードの記述
            channel.send(self.__password + "\n")
            RECV_SIZE = 1024 * 32

            while not channel.closed or channel.recv_ready() or channel.recv_stderr_ready():
                data = channel.recv(RECV_SIZE).decode('utf-8')

                #データがからの時は飛ばす
                if data == b'':
                    continue

                if 'tcpdump' in data or 'listening on' in data or 'connection timed out' in data:
                     continue

                #改行で区切る
                data = data.splitlines()
                for line in data:

                    # queueにデータを格納する
                    queue.put(line)

            code = channel.recv_exit_status()

        finally:
            channel.close()

    #引数にとったIPを持ったユーザーとの接続を拒否する
    def deny_connection(self, ip_address):
        stdin, stdout, stderr = self.client.exec_command("cat /etc/hosts.deny")

        #既に書き込みづみのユーザーは飛ばす
        for line in stdout:
            if re.search(r'{}'.format(ip_address), line) is not None:
                return

        #遮断するためのコマンド
        cmd = f'sudo echo "sshd: {ip_address}" >> /etc/hosts.deny'
        print(cmd)

        #コマンドを実行する
        stdin, stdout, stderr = self.client.exec_command(cmd, get_pty=True)
        stdin.write(self.__password + "\n")
        stdin.flush()
        print(f'{ip_address}の通信を遮断しました')

