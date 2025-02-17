import pandas as pd
from Data_analysis import final_data
pd.set_option('display.max_columns', 100)

# model = tf.keras.models.load_model("MLP_classifier.h5")

file = "Datasets/Predict_1.pcap"
input_df = final_data(file)

print(input_df.head(20))

# prediction = model.predict(input)
# print("Prediction", prediction)
