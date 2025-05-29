import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import pickle
import os

# Load dataset
df = pd.read_csv('E:/NM/Project/project/datasets/dataset.csv')

# Fill missing values/
df = df.fillna('')  # Replace NaNs with empty strings

# Combine all symptom columns into one set
symptom_columns = [col for col in df.columns if col.startswith("Symptom")]
all_symptoms = set()

for col in symptom_columns:
    all_symptoms.update(df[col].unique())

# Remove blanks and convert to sorted list
all_symptoms = sorted(symptom.strip().lower() for symptom in all_symptoms if symptom and symptom != '')

# One-hot encoding: create a column for each symptom
def encode_symptoms(row):
    symptoms_present = set(str(row[col]).strip().lower() for col in symptom_columns if row[col])
    return [1 if symptom in symptoms_present else 0 for symptom in all_symptoms]

# Build feature matrix
X = df.apply(encode_symptoms, axis=1, result_type='expand')
X.columns = all_symptoms

# Encode target (disease)
encoder = LabelEncoder()
y = encoder.fit_transform(df['Disease'])

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = RandomForestClassifier(n_estimators=100)
model.fit(X_train, y_train)

# Evaluate model
predictions = model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, predictions))

# Save model and encoder
os.makedirs('model', exist_ok=True)
with open('model/disease_prediction_model.pkl', 'wb') as f:
    pickle.dump(model, f)

with open('model/encoder.pkl', 'wb') as f:
    pickle.dump(encoder, f)

print("Model and encoder saved in /model/")