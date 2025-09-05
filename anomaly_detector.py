import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, LSTM, RepeatVector, TimeDistributed, Dense
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction import FeatureHasher
import joblib

# --- CONFIGURATION ---
TIMESTEPS = 10 # How many snapshots form a single sequence

# Define which columns are which type for preprocessing
CATEGORICAL_COLS = ['process_name', 'username']
NUMERICAL_COLS = ['cpu_percent', 'memory_percent', 'num_threads'] 
# The final number of features will be the sum of hashed features and numerical features
N_HASH_FEATURES = 5 
N_FEATURES = N_HASH_FEATURES + len(NUMERICAL_COLS)


class AdvancedLSTMAutoencoder:
    def __init__(self):
        self.model = None
        self.history = None
        # Initialize preprocessors that will be fitted on the data
        self.scaler = StandardScaler()
        self.hasher = FeatureHasher(n_features=N_HASH_FEATURES, input_type='string')

    def preprocess_data(self, df):
        """
        Processes the multi-feature dataframe into numerical sequences for the LSTM.
        """
        print("Preprocessing enhanced data...")

        # 1. Handle Categorical Features with Hashing
        categorical_data = df[CATEGORICAL_COLS].astype(str).to_dict('records')
        hashed_features = self.hasher.fit_transform(categorical_data).toarray()
        print(f"Hashed categorical features into shape: {hashed_features.shape}")

        # 2. Handle Numerical Features with Scaling
        numerical_data = df[NUMERICAL_COLS].values
        scaled_features = self.scaler.fit_transform(numerical_data)
        print(f"Scaled numerical features into shape: {scaled_features.shape}")

        # 3. Combine preprocessed features
        processed_features = np.hstack((hashed_features, scaled_features))
        print(f"Combined features into final shape: {processed_features.shape}")

        # 4. Create sequences from the combined features
        sequences = []
        for i in range(len(processed_features) - TIMESTEPS + 1):
            sequences.append(processed_features[i:i + TIMESTEPS])
            
        if not sequences:
            print("[ERROR] No sequences were created. The dataset is likely too small for the TIMESTEPS setting.")
            return np.array([])

        return np.array(sequences)

    def build_model(self):
        """
        Defines the architecture of the LSTM Autoencoder neural network.
        """
        inputs = Input(shape=(TIMESTEPS, N_FEATURES))
        # Encoder
        encoded = LSTM(128, activation='relu', return_sequences=False)(inputs)
        encoded = RepeatVector(TIMESTEPS)(encoded)
        
        # --- FIX IS HERE ---
        # Decoder now correctly takes the 'encoded' variable as input
        decoded = LSTM(128, activation='relu', return_sequences=True)(encoded)
        # --- END FIX ---

        output = TimeDistributed(Dense(N_FEATURES))(decoded)
        
        self.model = Model(inputs, output)
        self.model.compile(optimizer='adam', loss='mae')
        print(f"LSTM Autoencoder model built for {N_FEATURES} features.")
        self.model.summary()

    def train(self, sequences):
        """
        Trains the autoencoder on the preprocessed sequences of 'normal' activity.
        """
        print("\nStarting model training...")
        self.history = self.model.fit(
            sequences, sequences,
            epochs=30,
            batch_size=64,
            validation_split=0.1,
            shuffle=False,
            callbacks=[
                tf.keras.callbacks.EarlyStopping(monitor='val_loss', patience=5, mode='min', restore_best_weights=True)
            ]
        )
        print("Model training complete.")

    def find_anomaly_threshold(self, sequences):
        """
        Calculates a statistical threshold for identifying anomalies.
        """
        print("\nFinding anomaly threshold...")
        reconstructions = self.model.predict(sequences)
        train_mae_loss = np.mean(np.abs(reconstructions - sequences), axis=(1, 2))
        threshold = np.mean(train_mae_loss) + 3 * np.std(train_mae_loss)
        print(f"Reconstruction error threshold set to: {threshold}")
        return threshold

    def save_all(self, threshold, model_path="lstm_autoencoder.keras", scaler_path="scaler.gz", hasher_path="hasher.gz", threshold_path="threshold.txt"):
        """Saves the model, preprocessors, and threshold."""
        self.model.save(model_path)
        joblib.dump(self.scaler, scaler_path)
        joblib.dump(self.hasher, hasher_path)
        with open(threshold_path, 'w') as f:
            f.write(str(threshold))
        print(f"\nSuccessfully saved model, preprocessors, and threshold.")

# --- Main execution block ---
if __name__ == '__main__':
    try:
        dataframe = pd.read_csv('baseline_data.csv')
        dataframe = dataframe.drop(columns=['timestamp', 'pid'])
        print(f"Loaded {len(dataframe)} records from baseline_data.csv")
    except FileNotFoundError:
        print("[ERROR] baseline_data.csv not found. Please run data_collector.py first.")
        exit()
    except Exception as e:
        print(f"Error loading or parsing CSV: {e}")
        exit()

    autoencoder = AdvancedLSTMAutoencoder()
    training_sequences = autoencoder.preprocess_data(dataframe)
    
    if training_sequences.size > 0:
        autoencoder.build_model()
        autoencoder.train(training_sequences)
        threshold = autoencoder.find_anomaly_threshold(training_sequences)
        autoencoder.save_all(threshold=threshold)
        
        print("\n--- Training Process Complete ---")
        print("A new, more advanced model is ready for integration with Sentinel.")
