from sklearn.svm import SVC
from sklearn import preprocessing
import settings
import csv
import numpy as np

class MachineLerning(object):

    #パラメータ設定
    _C = 1.0
    _KERNEL = "linear"

    def __init__(self):
        self._mm = preprocessing.MinMaxScaler()
        self._svc = self._lerning_training_data()

    def _lerning_training_data(self):

        #SVCオブジェクトを作成
        svc = SVC(C=self._C, kernel=self._KERNEL)
        #学習用データを取得
        X, y = self._get_trainig_data()
        #データXを正規化
        self._mm.fit(X)
        X = self._mm.transform(X)
        #データを学習
        svc.fit(X, y)
        return svc

    def _get_trainig_data(self):
        path = settings.TRAINING_DATA_PATH
        x = []
        y = []
        with open(path, encoding='utf8', newline='') as file:
            csvreader = csv.reader(file)
            for row in csvreader:
                x.append([float(row[0]), float(row[1])])
                if row[-1] == "success":
                    y.append(1)
                else:
                    y.append(-1)
        X = np.array(x)
        y = np.array(y)
        return X, y

    #connection: np.array() ['packet', 'datasize']
    def judgeConnection(self, connection):
        connection = self._mm.transform(connection)
        result = self._svc.predict(connection)
        return result[0]