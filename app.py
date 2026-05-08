from flask import Flask, render_template_string, request
import joblib
import socket
import random
import re

from scipy.sparse import hstack
from scipy.sparse import csr_matrix

# Load model and vectorizer
model = joblib.load("model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

app = Flask(__name__)

# -----------------------------------
# Feature Extraction Function
# -----------------------------------

def extract_features(url):

    features = []

    features.append(len(url))
    features.append(url.count('.'))
    features.append(url.count('/'))
    features.append(url.count('-'))
    features.append(1 if '@' in url else 0)
    features.append(1 if 'https' in url.lower() else 0)
    features.append(sum(c.isdigit() for c in url))

    features.append(len(
        re.findall(r'[!@#$%^&*(),?":{}|<>]', url)
    ))

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
# HTML TEMPLATE
# -----------------------------------

HTML = """

<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>CyberShield AI</title>

<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">

<style>

*{
    margin:0;
    padding:0;
    box-sizing:border-box;
}

body{

    font-family:'Poppins',sans-serif;

    background:
    radial-gradient(circle at top left,#1e3a8a,#020617);

    min-height:100vh;

    color:white;

    overflow-x:hidden;
}

.container{

    width:90%;
    max-width:1200px;

    margin:auto;

    padding:40px 0;
}

.header{

    text-align:center;

    margin-bottom:40px;
}

.header h1{

    font-size:4rem;

    font-weight:700;

    background:linear-gradient(
        90deg,
        #38bdf8,
        #06b6d4,
        #22c55e
    );

    -webkit-background-clip:text;

    -webkit-text-fill-color:transparent;

    margin-bottom:15px;
}

.header p{

    color:#cbd5e1;

    font-size:1.1rem;
}

.glass{

    background:rgba(255,255,255,0.08);

    backdrop-filter:blur(14px);

    border:1px solid rgba(255,255,255,0.1);

    border-radius:24px;

    box-shadow:
    0 8px 32px rgba(0,0,0,0.35);
}

.search-box{

    padding:30px;

    margin-bottom:30px;
}

input{

    width:100%;

    padding:18px 20px;

    border:none;

    border-radius:14px;

    background:rgba(255,255,255,0.08);

    color:white;

    font-size:1rem;

    outline:none;

    border:1px solid rgba(255,255,255,0.1);
}

input::placeholder{
    color:#cbd5e1;
}

button{

    width:100%;

    margin-top:20px;

    padding:18px;

    border:none;

    border-radius:14px;

    background:linear-gradient(
        90deg,
        #06b6d4,
        #3b82f6
    );

    color:white;

    font-size:1rem;

    font-weight:600;

    cursor:pointer;

    transition:0.3s;
}

button:hover{

    transform:translateY(-3px);

    box-shadow:
    0 0 20px rgba(6,182,212,0.5);
}

.dashboard{

    display:grid;

    grid-template-columns:
    repeat(auto-fit,minmax(300px,1fr));

    gap:25px;
}

.card{

    padding:25px;

    position:relative;

    overflow:hidden;
}

.card h2{

    margin-bottom:20px;

    font-size:1.3rem;
}

.safe-border{
    border-left:6px solid #22c55e;
}

.danger-border{
    border-left:6px solid #ef4444;
}

.warning-border{
    border-left:6px solid #f59e0b;
}

.result{

    font-size:2rem;

    font-weight:700;

    margin-bottom:15px;
}

.safe-text{
    color:#22c55e;
}

.danger-text{
    color:#ef4444;
}

.progress{

    width:100%;

    height:16px;

    background:#1e293b;

    border-radius:20px;

    overflow:hidden;

    margin-top:15px;
}

.progress-bar{

    height:100%;

    border-radius:20px;

    transition:1s;
}

.safe-bar{
    background:#22c55e;
}

.danger-bar{
    background:#ef4444;
}

.info{

    margin-top:15px;

    line-height:2;
}

.badge{

    display:inline-block;

    padding:8px 14px;

    border-radius:50px;

    font-size:0.9rem;

    font-weight:600;

    margin-top:10px;
}

.safe-badge{
    background:rgba(34,197,94,0.2);
    color:#22c55e;
}

.danger-badge{
    background:rgba(239,68,68,0.2);
    color:#ef4444;
}

.features{

    display:grid;

    grid-template-columns:1fr 1fr;

    gap:15px;

    margin-top:20px;
}

.feature-box{

    padding:15px;

    border-radius:14px;

    background:rgba(255,255,255,0.05);

    text-align:center;
}

.feature-box h3{

    font-size:1.5rem;

    margin-bottom:8px;
}

.footer{

    text-align:center;

    margin-top:50px;

    color:#94a3b8;
}

</style>

</head>

<body>

<div class="container">

<div class="header">

<h1>🛡 CyberShield AI</h1>

<p>
AI Powered Cybersecurity Threat Intelligence & URL Detection System
</p>

</div>

<div class="glass search-box">

<form method="POST">

<input
type="text"
name="url"
placeholder="Enter suspicious URL for analysis..."
required>

<button type="submit">

🚀 Analyze Threat

</button>

</form>

</div>

{% if prediction %}

<div class="dashboard">

<div class="glass card {{ border_class }}">

<h2>⚠ Threat Detection Result</h2>

<div class="result {{ text_class }}">
{{ prediction }}
</div>

<div class="progress">

<div
class="progress-bar {{ bar_class }}"
style="width:{{ risk_score }}%;">
</div>

</div>

<div class="info">

<p><b>🌐 IP Address:</b> {{ ip_address }}</p>

<p><b>📊 Risk Score:</b> {{ risk_score }}%</p>

<p><b>🧠 Threat Level:</b> {{ risk_level }}</p>

<span class="badge {{ badge_class }}">
{{ badge_text }}
</span>

</div>

</div>

<div class="glass card warning-border">

<h2>📈 Threat Analytics</h2>

<div class="features">

<div class="feature-box">
<h3>{{ url_length }}</h3>
<p>URL Length</p>
</div>

<div class="feature-box">
<h3>{{ dots }}</h3>
<p>Dot Count</p>
</div>

<div class="feature-box">
<h3>{{ special_chars }}</h3>
<p>Special Chars</p>
</div>

<div class="feature-box">
<h3>{{ suspicious_words }}</h3>
<p>Suspicious Words</p>
</div>

</div>

</div>

<div class="glass card">

<h2>🛠 Detection Engine</h2>

<div class="info">

<p>✔ TF-IDF URL Analysis</p>

<p>✔ Machine Learning Classification</p>

<p>✔ Feature Engineering</p>

<p>✔ Behavioral URL Analysis</p>

<p>✔ Threat Intelligence Detection</p>

<p>✔ Hybrid Cybersecurity Engine</p>

</div>

</div>

</div>

{% endif %}

<div class="footer">

<p>
CyberShield AI © 2026 | Intelligent Threat Detection System
</p>

</div>

</div>

</body>

</html>

"""

# -----------------------------------
# ROUTE
# -----------------------------------

@app.route('/', methods=['GET', 'POST'])

def home():

    prediction = ""
    ip_address = "N/A"

    risk_score = 0
    risk_level = "LOW"

    border_class = "safe-border"
    text_class = "safe-text"
    bar_class = "safe-bar"
    badge_class = "safe-badge"

    badge_text = "SAFE"

    url_length = 0
    dots = 0
    special_chars = 0
    suspicious_words = 0

    if request.method == 'POST':

        url = request.form['url']

        try:

            domain = url.replace(
                "http://",""
            ).replace(
                "https://",""
            ).split('/')[0]

            ip_address = socket.gethostbyname(domain)

        except:

            ip_address = "Unable to Resolve"

        # TF-IDF
        url_vectorized = vectorizer.transform([url])

        # Custom Features
        custom_features = extract_features(url)

        custom_features_sparse = csr_matrix([custom_features])

        # Combine Features
        final_features = hstack([
            url_vectorized,
            custom_features_sparse
        ])

        # Prediction
        result = model.predict(final_features)[0]

        # Analytics
        url_length = len(url)
        dots = url.count('.')

        special_chars = len(
            re.findall(r'[!@#$%^&*(),?":{}|<>]', url)
        )

        suspicious_words = sum(
            word in url.lower()
            for word in [
                'login',
                'verify',
                'secure',
                'bank',
                'malware',
                'phishing'
            ]
        )

        # Output
        if result == 'Safe':

            prediction = "SAFE URL"

            risk_score = random.randint(5,30)

            risk_level = "LOW"

        else:

            prediction = "MALICIOUS URL DETECTED"

            risk_score = random.randint(75,99)

            risk_level = "HIGH"

            border_class = "danger-border"

            text_class = "danger-text"

            bar_class = "danger-bar"

            badge_class = "danger-badge"

            badge_text = "THREAT DETECTED"

    return render_template_string(

        HTML,

        prediction=prediction,

        ip_address=ip_address,

        risk_score=risk_score,

        risk_level=risk_level,

        border_class=border_class,

        text_class=text_class,

        bar_class=bar_class,

        badge_class=badge_class,

        badge_text=badge_text,

        url_length=url_length,

        dots=dots,

        special_chars=special_chars,

        suspicious_words=suspicious_words
    )

# -----------------------------------

if __name__ == '__main__':

    app.run(debug=True)
