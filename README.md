# Network-log-classifier

An Intrusion Detection System(IDS) concept based classifier that
uses the UNSW-NB15 Dataset to train a neural network model to
predict the type of attack that are present in a .pcap file.
The attack types that these models are trained for are;
'Analysis','Backdoor','DoS','Exploits','Fuzzers','Generic','Normal','Reconnaissance','Shellcode','Worms'

- `strategy.py` holds the class for strategy for models to use. 
Multi-Layer Perceptron(MLP), Convolutional Neural Network(CNN), and 
Recurrent Neural Network(RNN). Also the funcitions used to train and test the models.

- `context.py` has the program I used to define the input funtion and data normalization 
I used to train and test the models.

- `main.py` is the main program where I pass the input files to predict classifications.
I also used a partition of the dataset to calculate various result parameters which I use
to evaluate a model's usefulness.

- `Data_analysis.py` holds the various tools and algorithms I plan to use to calculate various feature
variables present in UNSW-NB15 dataset, from a .pcap file. I plan to program it so that I will be able
to input a raw .pcap file for classification.

## **Multi-layer Perceptrons**

Inspired from the research paper; 

`Z. Wang, "Deep Learning-Based Intrusion Detection With Adversaries," in IEEE Access, vol. 6, pp. 38367-38384, 2018, doi: 10.1109/ACCESS.2018.2854599.`


Results:

Accuracy:  0.5216432902164329

Classification report:

| classes | precision | recall | f1-score |  support |
|---------|-----------|--------|----------|----------|
|Analysis    |   0.00   |   0.00  |    0.00   |    670  |
|Backdoor    |   0.14   |  0.01   |   0.02    |   666  |
|     DoS    |   0.01   |   0.11  |    0.02   |   4907  |
|Exploits    |   0.12   |   0.93  |    0.21   |  11439  |
|Fuzzers     |   0.42   |   0.41  |    0.42   |   5390  |
|  Generic   |   0.48   |   0.97  |    0.64   |  61878  |
|  Normal    |   1.00   |   0.44  |    0.61   | 351150  |
|Reconnaissance    |   0.25   |   0.41    |  0.31   |   3530 |
|Shellcode    |   0.35   |   0.12  |    0.18   |    371 |
|   Worms     |  0.38    |  0.12   |   0.18    |    43 |
|accuracy     |          |         |  0.52  |  440044 |
|macro avg    |  0.32    |  0.35   |   0.26  |  440044 |
|weighted avg  |     0.88  |    0.52  |    0.59  |  440044 |


