import pandas as pd
import re
from models import session
from models import Packet, Connection, User
import numpy as np
from controllers.discrimination_model import MachineLerning


class Controller(object):

    def __init__(self):
        #コネクションの状況を一時的に保存する
        self._connection_state = {}
        #SVMに学習させる。
        self.machine_lerning = MachineLerning()

    def main(self, queue, deny_func):

        while True:

            # 出力されたデータを一行づつ取得する
            line = queue.get()

            print('[line]: ', line)

            # packetsテーブルに反映できる表示に変更する
            packet = self._normalization(line)

            #パケットデータ以外の場合は飛ばす。
            if packet is None:
                continue

            #packetテーブルに追記
            self._insert_record_to_packet_table(
                ip=packet['ip'],
                flags=packet['flags'],
                length=packet['length']
            )

            #packetのipアドレスとポート番号を切り離す
            ip = '.'.join([num for num in packet['ip'].split('.')[:-1]])
            port = packet['ip'].split('.')[-1]

            #初めて接続するユーザーはuserテーブルに追加する
            a_user = self._get_user_record_from_user_table(ip=ip)
            if a_user == None:
                self._insert_record_to_user_table(ip, consecutive_failure=0)

            #コネクションを検知する。self._connection_stateを上書きする
            connection = self._detect_connection_and_dump_state(packet)

            #新しいコネクションができなかったら次のパケットを参照
            if connection == None:
                continue

            #攻撃者かどうかを判断
            attacker_or_regular = self._attacker_judgement(ip=connection['ip'], result=connection['result'])

            #正規ユーザーと判定された時
            if attacker_or_regular == None:
                continue

            #攻撃者として判定
            self._deny_connect(func=deny_func, ip_address=attacker_or_regular)

    #パケットからipアドレス、flags、データ長、を取り出す
    def _normalization(self, resultLine: str) -> dict:

        try:
            IP = re.findall(r'((\d+)\.(\d+)\.(\d+)\.(\d+))\.(\d+)', resultLine)  # \.(\d+)
            fromIP = IP[0][0]
            fromPort = IP[0][5]
            toIP = IP[1][0]
            toPort = IP[1][5]
            #sshに接続しているホストをipに設定
            if fromPort == "22":
                ip = toIP + '.' + toPort
            elif toPort == "22":
                ip = fromIP + '.' + fromPort
            else:
                print('I do not know')
            flags = re.search(r'(Flags )(\[)([SFPRWE.]*)(])', resultLine)
            if flags is None:
                flags = np.nan
            else:
                flags = flags.group(3)
            length = re.search(r'(length )(\d+)$', resultLine)
            if length is not None:
                length = int(length.group(2))
            else:
                length = 0
            data = {'ip': ip, 'flags': flags, 'length': length}

        except:
            data = None

        return data

    #パケットからコネクションを検知する関数
    def _detect_connection_and_dump_state(self, packet):

        # packet : ip, flags, length
        ip = packet['ip']
        flags = packet['flags']
        length = packet['length']

        try:
            if flags == "R." or flags == "R":
                self._connection_state[ip][0] += 1
                self._connection_state[ip][1] += length

                packets = self._connection_state[ip][0]
                datasize = self._connection_state[ip][1]

                self._connection_state.pop(ip)

                ip = '.'.join([num for num in ip.split('.')[:-1]])

                # コネクションの成否
                result = self._judge_connection(packets=packets, datasize=datasize)

                #connectionテーブルにパケットを追加する処理
                self._insert_record_to_connection_table(
                    ip=ip,
                    packets=packets,
                    datasize=datasize,
                    login_result=result
                )
                return {'ip': ip, 'packets': packets, 'datasize': datasize, 'result': result}

            elif flags == "F.":
                self._connection_state[ip][0] += 1
                self._connection_state[ip][1] += length

                packets = self._connection_state[ip][0]
                datasize = self._connection_state[ip][1]

                print('削除前', self._connection_state, '\n', ip)
                self._connection_state.pop(ip)
                print('削除後', self._connection_state)

                ip = '.'.join([num for num in ip.split('.')[:-1]])

                # コネクションの成否
                result = self._judge_connection(packets=packets, datasize=datasize)

                # connectionテーブルにパケットを追加する処理
                self._insert_record_to_connection_table(
                    ip=ip,
                    packets=packets,
                    datasize=datasize,
                    login_result=result
                )

                return {'ip': ip, 'packets': packets, 'datasize': datasize, 'result': result}

            elif flags == "S" or flags == "SEW":
                append_data = [1, 1]
                self._connection_state[ip] = append_data
                return None

            elif flags == "S.":
                self._connection_state[ip][0] += 1
                self._connection_state[ip][1] += length
                return None

            else:
                self._connection_state[ip][0] += 1
                self._connection_state[ip][1] += length
                return None

        #self._connection_state.loc[packet['ip']]が存在しないときなど。
        except:
            return

    def _insert_record_to_packet_table(self, ip, flags, length):
        a_packet = Packet(ip=ip, flags=flags, length=length)
        session.add(a_packet)
        session.commit()

    def _insert_record_to_connection_table(self, ip, packets, datasize, login_result):
        a_connection = Connection(ip=ip, packets=packets, datasize=datasize, login_result=login_result)
        session.add(a_connection)
        session.commit()


    def _insert_record_to_user_table(self, ip, consecutive_failure):
        a_user = User(ip=ip, consecutive_failure=consecutive_failure)
        session.add(a_user)
        session.commit()

    def _update_consecutive_failure(self, ip, consecurtive_failure_num):
        a_user = session.query(User).filter(User.ip == ip).first()
        a_user.consecutive_failure = consecurtive_failure_num
        session.add(a_user)
        session.commit()

    def _get_user_record_from_user_table(self, ip):
        a_user = session.query(User).filter(User.ip == ip).first()
        return a_user

    def _judge_connection(self, packets, datasize):

        # パケットが100以上の場合は、正規ユーザー
        if packets >= 100:
            result = 1
            return result

        #パケットが30未満の場合は、ログイン失敗
        elif packets < 30:
            result = -1
            return result

        else:
            connection = np.array([[float(packets), float(datasize)]])
            # 機械学習で予測データを返す
            result = self.machine_lerning.judgeConnection(
                connection=connection
            )

        # result = 1 の時、成功。-1の時、失敗
        return result

    def _attacker_judgement(self, ip, result):

        # 許容連続失敗回数
        n = 20

        # 以前までの接続を取得
        a_user = session.query(User).filter(User.ip == ip).first()
        if a_user == None:
            return None

        consecutive_failure_num = a_user.consecutive_failure

        # 以前に接続してなかった場合
        if consecutive_failure_num is None:
            consecutive_failure_num = 0

        #接続が失敗していた場合
        if result == 1:
            consecutive_failure_num = 0
        else:
            consecutive_failure_num += 1

        # データベースに反映させる
        self._update_consecutive_failure(ip=ip, consecurtive_failure_num=consecutive_failure_num)

        # 許容連続失敗回数を上回った場合、そのIPアドレスの接続を行わない
        if consecutive_failure_num >= n:
            return ip
        else:
            return None

    #deny_connectionを受け取って実行
    def _deny_connect(self, func, ip_address):
        func(ip_address)



