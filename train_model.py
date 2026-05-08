import pandas as pd
import re
import joblib

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from scipy.sparse import hstack
from scipy.sparse import csr_matrix

# Load dataset
data = pd.read_csv("dataset.csv")

# Features and labels
X = data["URL"]
y = data["Label"]

# -----------------------------------
# URL Feature Extraction Function
# -----------------------------------

def extract_features(url):

    features = []

    # URL length
    features.append(len(url))

    # Number of dots
    features.append(url.count('.'))

    # Number of slashes
    features.append(url.count('/'))

    # Number of hyphens
    features.append(url.count('-'))

    # Contains @ symbol
    features.append(1 if '@' in url else 0)

    # HTTPS check
    features.append(1 if 'https' in url.lower() else 0)

    # Digit count
    features.append(sum(c.isdigit() for c in url))

    # Special character count
    features.append(len(
        re.findall(r'[!@#$%^&*(),?":{}|<>]', url)
    ))

    # Suspicious keywords
    suspicious_words = [
        'login',
        'verify',
        'account',
        'secure',
        'update',
        'bank',
        'signin',
        'admin',
        'malware',
        'phishing',
        'virus',
        'trojan',
        'shell'
    ]

    suspicious_count = sum(
        word in url.lower()
        for word in suspicious_words
    )

    features.append(suspicious_count)

    return features

# -----------------------------------
# Extract Custom Features
# -----------------------------------

custom_features = [extract_features(url) for url in X]

custom_features_sparse = csr_matrix(custom_features)

# -----------------------------------
# TF-IDF Vectorization
# -----------------------------------

vectorizer = TfidfVectorizer()

X_vectorized = vectorizer.fit_transform(X)

# -----------------------------------
# Combine TF-IDF + Custom Features
# -----------------------------------

X_combined = hstack([
    X_vectorized,
    custom_features_sparse
])

# -----------------------------------
# Split Dataset
# -----------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X_combined,
    y,
    test_size=0.2,
    random_state=42
)

# -----------------------------------
# Train Model
# -----------------------------------

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42
)

model.fit(X_train, y_train)

# -----------------------------------
# Test Accuracy
# -----------------------------------

predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print("Model Accuracy:", accuracy)

# -----------------------------------
# Save Model
# -----------------------------------

joblib.dump(model, "model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")

print("Improved model trained successfully")
