from abc import ABC, abstractmethod
import tensorflow as tf

class ModelStrategy(ABC):
    @abstractmethod
    def build_model(self, input_shape, num_classes):
        pass

class MLPModel(ModelStrategy):
    def build_model(self, input_shape, num_classes):
        model = tf.keras.Sequential([
            tf.keras.layers.Input(shape=(input_shape,)),
            tf.keras.layers.Flatten(),
            tf.keras.layers.Dense(256, activation='relu'),
            tf.keras.layers.Dropout(0.4),
            tf.keras.layers.Dense(256, activation='relu'),
            tf.keras.layers.Dropout(0.4),
            tf.keras.layers.Dense(num_classes, activation='softmax')
        ])
        return model

class ModelTrainer:
    def __init__(self, model_strategy: ModelStrategy):
        self.model_strategy = model_strategy
        self.model = None

    def set_model_strategy(self, model_strategy: ModelStrategy):
        self.model_strategy = model_strategy

    def train_model(self, x_train_data, y_train_data, input_shape, num_classes, epochs=10):
        self.model = self.model_strategy.build_model(input_shape, num_classes)
        self.model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
        return self.model.fit(x_train_data, y_train_data, epochs=epochs, batch_size=128, validation_split=0.1, shuffle=True)
    def test_model(self, x_test_data, y_test_data):
        loss, accuracy = self.model.evaluate(x_test_data, y_test_data, batch_size=128)
        print(f"Test Loss: {loss}")
        print(f"Test Accuracy: {accuracy}")
        return
