import pandas as pd
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import os

# Load dataset
try:
    dataset = pd.read_csv('datasets/dataset.csv')
except FileNotFoundError:
    print("Error: 'datasets/dataset.csv' not found.")
    exit(1)

# Clean column names
dataset.columns = dataset.columns.str.strip().str.replace(' ', '_').str.lower()

# Log dataset info
print(f"Dataset shape: {dataset.shape}")
print(f"Columns: {list(dataset.columns)}")

# Check if dataset has string-based symptom columns (e.g., symptom_1, symptom_2)
symptom_columns = [col for col in dataset.columns if col.startswith('symptom_')]

if symptom_columns:
    print(f"Found string-based symptom columns: {symptom_columns}")
    # Get all unique symptoms
    all_symptoms = set()
    for col in symptom_columns:
        all_symptoms.update(dataset[col].dropna().unique())
    
    print(f"Unique symptoms: {len(all_symptoms)}")
    
    # Create binary columns for all symptoms at once
    binary_columns = {}
    for symptom in all_symptoms:
        symptom_clean = symptom.strip().replace(' ', '_').lower()
        binary_columns[symptom_clean] = dataset[symptom_columns].apply(
            lambda row: 1 if symptom in row.values else 0, axis=1
        )
    
    # Concatenate all binary columns to the dataset
    binary_df = pd.DataFrame(binary_columns)
    dataset = pd.concat([dataset, binary_df], axis=1)
    
    # Drop original symptom columns
    dataset = dataset.drop(columns=symptom_columns)
else:
    print("Assuming dataset is already in binary format.")

# Prepare features and target
if 'disease' not in dataset.columns:
    print("Error: 'disease' column not found in dataset.")
    exit(1)

X = dataset.drop('disease', axis=1)
y = dataset['disease']

# Encode target
encoder = LabelEncoder()
y_encoded = encoder.fit_transform(y)

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X, y_encoded)

# Save model and encoder
os.makedirs('model', exist_ok=True)
pickle.dump(model, open('model/disease_prediction_model.pkl', 'wb'))
pickle.dump(encoder, open('model/encoder.pkl', 'wb'))

print("Model retrained and saved. Feature names:", model.feature_names_in_)