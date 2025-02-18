import tensorflow as tf
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import OneHotEncoder, StandardScaler
import numpy as np

pd.set_option('display.max_columns', 100)

def normalize_data(data):
    attack_cat = ['Analysis', 'Backdoor', 'DoS', 'Exploits', 'Fuzzers', 'Generic', 'Normal', 'Reconnaissance',
                  'Shellcode', 'Worms']
    #change input data to the same format as training data
    label = data['attack_cat']
    label.fillna('Normal', inplace=True)
    data.drop(columns=['srcip', 'sport', 'dstip', 'dport', 'stime', 'dtime', 'attack_cat', 'label'], inplace=True)
    data.replace(' ', np.nan, inplace=True)
    data.fillna(0, inplace=True)
    data = pd.get_dummies(data, columns=['proto','service','state'])
    label = pd.get_dummies(label, columns=['attack_cat'])
    label.columns = label.columns.str.strip()
    label = label[attack_cat]
    features = pd.read_csv("features.csv")
    data, _ = data.align(features, join='right', axis=1, fill_value=0)
    data.columns = data.columns.astype(str)
    scaler = StandardScaler()
    data = scaler.fit_transform(data.astype(float))
    return data, label

column_names = ['srcip', 'sport', 'dstip', 'dport', 'proto', 'state', 'dur', 'sbytes', 'dbytes', 'sttl', 'dttl','sloss', 'dloss',
                     'service', 'sload', 'dload', 'spkts', 'dpkts', 'swin', 'dwin', 'stcpb', 'dtcpb',
                     'smean', 'dmean', 'trans_depth', 'response_body_len', 'sjit', 'djit', 'stime', 'dtime',
                     'sinpkt', 'dinpkt', 'tcprtt', 'synack', 'ackdat', 'is_sm_ips_ports', 'ct_state_ttl',
                     'ct_flw_http_mthd', 'is_ftp_login', 'ct_ftp_cmd', 'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm',
                     'ct_src_ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'attack_cat', 'label']
attack_cat = ['Analysis', 'Backdoor', 'DoS', 'Exploits', 'Fuzzers', 'Generic', 'Normal', 'Reconnaissance',
                  'Shellcode', 'Worms']
input_data = pd.read_csv("Datasets/UNSW-NB15_4.csv", header=None, index_col=False, names=column_names)
input_df, label = normalize_data(input_data)
model = tf.keras.models.load_model("MLP_classifier.h5")
y_pred = model.predict(input_df)
y_pred = np.argmax(y_pred, axis=1)  # Now it's in the format of class indices (0, 1)
label = np.argmax(label, axis=1)  # Convert true labels to class indices as well
accuracy = accuracy_score(label, y_pred)
print("Accuracy: ", accuracy)
report = classification_report(label, y_pred, target_names=attack_cat)
print("Classification report:\n ", report)

