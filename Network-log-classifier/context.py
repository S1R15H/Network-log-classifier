from sklearn.preprocessing import OneHotEncoder, StandardScaler
import numpy as np
import pandas as pd
from strategy import *

# DATA PREPROCESSING....

train_df = pd.read_csv("Datasets/UNSW_NB15_training-set.csv")  #Dataframe to train
test_df = pd.read_csv("Datasets/UNSW_NB15_testing-set.csv")  #Dataframe to test
train_df.dropna(inplace=True) #Removes empty rows
test_df.dropna(inplace=True)

# the csv file has a pre-determined label to see if the packets are a form of attack or not
# I am going to use the attack categories as a label
train_df.drop(columns=['id', 'label'])
test_df.drop(columns=['id', 'label'])

#Attack categories..
attack_cat = ['Analysis','Backdoor','DoS','Exploits','Fuzzers','Generic','Normal','Reconnaissance','Shellcode','Worms']

# splitting training data and labels
x_train = train_df.drop(columns=['attack_cat'])
y_train = train_df['attack_cat']
x_test = test_df.drop(columns=['attack_cat'])
y_test = test_df['attack_cat']


#One-Hot encoding categorical data
x_train_df = pd.get_dummies(x_train, columns=['proto','service','state'])
y_train_df = pd.get_dummies(y_train, columns=['attack_cat'])
x_test_df = pd.get_dummies(x_test, columns=['proto','service','state'])
y_test_df = pd.get_dummies(y_test, columns=['attack_cat'])
x_train_df, x_test_df = x_train_df.align(x_test_df, join='left', axis=1, fill_value=0)

#data normalization
scaler = StandardScaler()
x_train_df = scaler.fit_transform(x_train_df.astype(float))  # Normalize all columns except labels
x_test_df = scaler.fit_transform(x_test_df.astype(float))

x_train_np = np.array(x_train_df)
y_train_np = np.array(y_train_df)
x_test_np = np.array(x_test_df)
y_test_np = np.array(y_test_df)

# Using training models
trainer = ModelTrainer(MLPModel())
history = trainer.train_model(x_train_np, y_train_np, x_train_np.shape[1], len(attack_cat))
trainer.test_model(x_test_np, y_test_np)
trainer.model.save("MLP_classifier.h5")
