import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import pandas as pd
import joblib

# Load dataset
data = pd.read_csv('datasetforproject_UPDATED.csv')
features = ['L4_SRC_PORT', 'TCP_FLAGS', 'L4_DST_PORT', 'PROTOCOL', 'L7_PROTO']
target = 'Label'

X = data[features]
y = data[target]

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Standardize features
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# Define model
model = Sequential([
    Dense(units=4, activation='relu', input_dim=X_train.shape[1]),
    Dense(units=1, activation='sigmoid')
])

# Compile model
model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

# Train model
model.fit(X_train, y_train, epochs=10, batch_size=128, validation_split=0.2)

# Save model and scaler
model.save('model.h5')  # Correct way to save a Keras model
joblib.dump(scaler, 'scaler.joblib')  # Save the scaler


