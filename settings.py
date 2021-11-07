import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

#秘密鍵のpathを表示する
KEY_ROOT = "interceptors/privateKeys/id_rsa"

#training.csvデータのpath
TRAINING_DATA_PATH = "controllers/training.csv"
