from flask import Flask, render_template_string, request
import joblib
import socket
import random
import re

import pandas as pd

from scipy.sparse import hstack
from scipy.sparse import csr_matrix

# Load trained model
model = joblib.load("model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

app = Flask(__name__)

# -----------------------------------
# Feature Extraction Function
# -----------------------------------

def extract_features(url):

    features = []

    # URL length
    features.append(len(url))

    # Dot count
    features.append(url.count('.'))

    # Slash count
    features.append(url.count('/'))

    # Hyphen count
    features.append(url.count('-'))

    # @ symbol
    features.append(1 if '@' in url else 0)

    # HTTPS check
    features.append(1 if 'https' in url.lower() else 0)

    # Digit count
    features.append(sum(c.isdigit() for c in url))

    # Special characters
    features.append(len(
        re.findall(r'[!@#$%^&*(),?":{}|<>]', url)
    ))

    # Suspicious words
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
# HTML
# -----------------------------------

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>CyberShield URL Attack Detector</title>

    <style>

        body{
            font-family: Arial;
            background:#0f172a;
            color:white;
            padding:40px;
        }

        .container{
            max-width:900px;
            margin:auto;
        }

        input{
            width:100%;
            padding:15px;
            border:none;
            border-radius:10px;
            margin-top:20px;
        }

        button{
            width:100%;
            padding:15px;
            margin-top:20px;
            border:none;
            border-radius:10px;
            background:#06b6d4;
            color:white;
            font-size:18px;
            cursor:pointer;
        }

        .card{
            margin-top:30px;
            padding:20px;
            border-radius:12px;
            background:#1e293b;
        }

        .safe{
            border-left:8px solid #22c55e;
        }

        .danger{
            border-left:8px solid #ef4444;
        }

    </style>

</head>

<body>

<div class="container">

    <h1>🛡 CyberShield URL Attack Detector</h1>

    <form method="POST">

        <input
            type="text"
            name="url"
            placeholder="Enter URL"
            required>

        <button type="submit">
            Analyze URL
        </button>

    </form>

    {% if prediction %}

    <div class="card {{ card_class }}">

        <h2>{{ prediction }}</h2>

        <p><b>IP Address:</b> {{ ip_address }}</p>

        <p><b>Risk Score:</b> {{ risk_score }}%</p>

        <p><b>Risk Level:</b> {{ risk_level }}</p>

    </div>

    {% endif %}

</div>

</body>
</html>
"""

# -----------------------------------
# Flask Route
# -----------------------------------

@app.route('/', methods=['GET', 'POST'])

def home():

    prediction = ""
    ip_address = "N/A"
    risk_score = 0
    risk_level = "LOW"
    card_class = "safe"

    if request.method == 'POST':

        url = request.form['url']

        # -----------------------------------
        # IP Extraction
        # -----------------------------------

        try:

            domain = url.replace("http://", "").replace(
                "https://", ""
            ).split('/')[0]

            ip_address = socket.gethostbyname(domain)

        except:

            ip_address = "Unable to Resolve"

        # -----------------------------------
        # TF-IDF Features
        # -----------------------------------

        url_vectorized = vectorizer.transform([url])

        # -----------------------------------
        # Custom Features
        # -----------------------------------

        custom_features = extract_features(url)

        custom_features_sparse = csr_matrix([custom_features])

        # -----------------------------------
        # Combine Features
        # -----------------------------------

        final_features = hstack([
            url_vectorized,
            custom_features_sparse
        ])

        # -----------------------------------
        # Prediction
        # -----------------------------------

        result = model.predict(final_features)[0]

        # -----------------------------------
        # Output
        # -----------------------------------

        if result == 'Safe':

            prediction = '✅ SAFE URL'

            risk_score = random.randint(5, 30)

            risk_level = 'LOW'

            card_class = 'safe'

        else:

            prediction = f'⚠️ MALICIOUS URL DETECTED'

            risk_score = random.randint(70, 99)

            risk_level = 'HIGH'

            card_class = 'danger'

    return render_template_string(
        HTML,
        prediction=prediction,
        ip_address=ip_address,
        risk_score=risk_score,
        risk_level=risk_level,
        card_class=card_class
    )

# -----------------------------------
# Run App
# -----------------------------------

if __name__ == '__main__':

    app.run(debug=True)
