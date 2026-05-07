import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.ensemble import RandomForestClassifier
import joblib

# Load dataset
data = pd.read_csv("dataset.csv")

# Features and labels
X = data["URL"]
y = data["Label"]

# Convert URLs into numbers
vectorizer = CountVectorizer()

X_vectorized = vectorizer.fit_transform(X)

# Train model
model = RandomForestClassifier()

model.fit(X_vectorized, y)

# Save trained model
joblib.dump(model, "model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")

print("Model trained successfully")