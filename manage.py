from controllers import control
from interceptors import ssh_auth
import queue
import _thread

def manage():

    ssh = ssh_auth.SSHConnector()

    controller = control.Controller()

    #queueオブジェクトを作成する
    q = queue.Queue()

    print('準備が整いました。これからコマンドを実行します。')

    # データベースの処理を行うタスク(並行処理)
    _thread.start_new_thread(controller.main, (q, ssh.deny_connection))

    # SSH接続とコマンド実行(並行処理)
    while True:
        ssh.exec_command(queue=q)

if __name__ == "__main__":
    manage()