import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, LSTM, RepeatVector
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction import FeatureHasher

class LSTMAutoencoder:
    """
    Handles the creation, training, and evaluation of the LSTM Autoencoder model.
    """
    def __init__(self, timesteps=10, n_features=5):
        self.model = None
        self.history = None
        self.timesteps = timesteps
        self.n_features = n_features
        self.scaler = StandardScaler()
        self.hasher = FeatureHasher(n_features=self.n_features, input_type='string')

    def preprocess_data(self, df):
        """
        Converts the raw log data from the CSV into numerical sequences for the LSTM.
        """
        print("Preprocessing data...")
        # Ensure the column is treated as strings
        process_names = df['process_name'].astype(str).to_list()
        
        # --- FIX IS HERE ---
        # The FeatureHasher expects a list of lists. We wrap each process name in its own list.
        formatted_for_hashing = [[name] for name in process_names]
        
        # Use the correctly formatted list for hashing
        hashed_features = self.hasher.fit_transform(formatted_for_hashing).toarray()
        # --- END FIX ---
        
        # Scale the features
        scaled_features = self.scaler.fit_transform(hashed_features)
        
        # Create sequences of data
        sequences = []
        for i in range(len(scaled_features) - self.timesteps + 1):
            sequences.append(scaled_features[i:i + self.timesteps])
            
        return np.array(sequences)

    def build_model(self):
        """
        Defines the architecture of the LSTM Autoencoder neural network.
        """
        inputs = Input(shape=(self.timesteps, self.n_features))
        encoded = LSTM(128, activation='relu')(inputs)
        decoded = RepeatVector(self.timesteps)(encoded)
        decoded = LSTM(128, activation='relu', return_sequences=True)(decoded)
        output = tf.keras.layers.TimeDistributed(tf.keras.layers.Dense(self.n_features))(decoded)
        
        self.model = Model(inputs, output)
        self.model.compile(optimizer='adam', loss='mae')
        print("LSTM Autoencoder model built successfully.")
        self.model.summary()

    def train(self, sequences):
        """
        Trains the autoencoder on the preprocessed sequences of 'normal' activity.
        """
        if self.model is None:
            print("Model has not been built yet. Call build_model() first.")
            return

        print("\nStarting model training... This may take a while.")
        self.history = self.model.fit(
            sequences, sequences,
            epochs=20,
            batch_size=32,
            validation_split=0.1,
            shuffle=False
        )
        print("Model training complete.")

    def find_anomaly_threshold(self, sequences):
        """
        Calculates the reconstruction error threshold to identify anomalies.
        """
        print("\nFinding anomaly threshold...")
        reconstructions = self.model.predict(sequences)
        train_mae_loss = np.mean(np.abs(reconstructions - sequences), axis=(1, 2))
        
        threshold = np.max(train_mae_loss) * 1.1
        print(f"Reconstruction error threshold set to: {threshold}")
        return threshold

    def save_model(self, path="lstm_autoencoder.h5"):
        """Saves the trained model to a file."""
        if self.model:
            self.model.save(path)
            print(f"Model saved to {path}")

# --- Main execution block to run the training process ---
if __name__ == '__main__':
    try:
        dataframe = pd.read_csv('baseline_data.csv')
        print(f"Loaded {len(dataframe)} log entries from baseline_data.csv")
    except FileNotFoundError:
        print("[ERROR] baseline_data.csv not found. Please run data_collector.py first.")
        exit()

    autoencoder = LSTMAutoencoder()
    training_sequences = autoencoder.preprocess_data(dataframe)
    autoencoder.build_model()
    autoencoder.train(training_sequences)
    threshold = autoencoder.find_anomaly_threshold(training_sequences)
    autoencoder.save_model()
    
    print("\n--- Training Process Complete ---")
    print("A trained model 'lstm_autoencoder.h5' and its settings are now ready for integration.")
