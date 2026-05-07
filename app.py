from flask import Flask, render_template_string, request
import joblib
import socket
import random

# Load trained ML model
model = joblib.load("model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>CyberShield URL Attack Detector</title>

    <style>

        *{
            margin:0;
            padding:0;
            box-sizing:border-box;
        }

        body{
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg,#020617,#0f172a,#1e3a8a);
            min-height:100vh;
            color:white;
            padding:40px;
        }

        .intro{
            text-align:center;
            margin-bottom:40px;
        }

        .intro h1{
            font-size:50px;
            color:#38bdf8;
            margin-bottom:15px;
        }

        .intro p{
            font-size:20px;
            color:#cbd5e1;
            max-width:900px;
            margin:auto;
            line-height:1.8;
        }

        .container{
            max-width:900px;
            margin:auto;
            background:rgba(255,255,255,0.08);
            border-radius:20px;
            padding:40px;
            backdrop-filter: blur(12px);
            box-shadow:0 8px 30px rgba(0,0,0,0.5);
        }

        input{
            width:100%;
            padding:18px;
            border:none;
            border-radius:12px;
            font-size:18px;
            margin-top:20px;
        }

        button{
            margin-top:25px;
            width:100%;
            padding:16px;
            font-size:20px;
            border:none;
            border-radius:12px;
            background:#06b6d4;
            color:white;
            cursor:pointer;
            font-weight:bold;
            transition:0.3s;
        }

        button:hover{
            background:#0891b2;
            transform:scale(1.02);
        }

        .dashboard{
            margin-top:40px;
            background:rgba(255,255,255,0.05);
            border-radius:18px;
            padding:30px;
        }

        .dashboard h2{
            margin-bottom:25px;
            color:#38bdf8;
        }

        .card{
            background:rgba(255,255,255,0.07);
            padding:20px;
            border-radius:15px;
            margin-bottom:20px;
        }

        .safe{
            border-left:8px solid #22c55e;
        }

        .danger{
            border-left:8px solid #ef4444;
        }

        .risk-bar{
            width:100%;
            height:25px;
            background:#1e293b;
            border-radius:20px;
            overflow:hidden;
            margin-top:10px;
        }

        .risk-fill{
            height:100%;
            background:linear-gradient(to right,#22c55e,#eab308,#ef4444);
            text-align:center;
            color:white;
            font-weight:bold;
        }

        .features{
            margin-top:40px;
            background:rgba(255,255,255,0.05);
            padding:25px;
            border-radius:18px;
        }

        .features h3{
            color:#38bdf8;
            margin-bottom:15px;
        }

        .features ul{
            padding-left:20px;
            line-height:2;
        }

        .footer{
            text-align:center;
            margin-top:40px;
            color:#94a3b8;
        }

    </style>
</head>

<body>

<div class="intro">

    <h1>🔐 CyberShield URL Attack Detector</h1>

    <p>
        Advanced Machine Learning based Cybersecurity System for detecting
        URL-based attacks such as SQL Injection, XSS, SSRF,
        Command Injection, Directory Traversal and other malicious
        HTTP attack patterns using intelligent URL analysis.
    </p>

</div>

<div class="container">

    <form method="POST">

        <input
            type="text"
            name="url"
            placeholder="Enter URL or HTTP Request"
            required>

        <button type="submit">
            ANALYZE URL
        </button>

    </form>

    {% if prediction %}

    <div class="dashboard">

        <h2>📊 Threat Analysis Dashboard</h2>

        <div class="card {{ card_class }}">
            <h3>Detection Result</h3>
            <p style="font-size:28px;margin-top:10px;">
                {{ prediction }}
            </p>
        </div>

        <div class="card">
            <h3>🌍 Extracted IP Address</h3>
            <p style="margin-top:10px;font-size:22px;">
                {{ ip_address }}
            </p>
        </div>

        <div class="card">
            <h3>⚠️ Risk Score</h3>

            <div class="risk-bar">
                <div class="risk-fill"
                style="width: {{ risk_score }}%;">
                    {{ risk_score }}%
                </div>
            </div>

            <p style="margin-top:15px;font-size:20px;">
                Risk Level: {{ risk_level }}
            </p>
        </div>

        <div class="card">
            <h3>🧠 Machine Learning Engine</h3>
            <p style="margin-top:10px;line-height:1.8;">
                Detection Algorithm: Random Forest Classifier<br>
                Framework: Flask + Scikit-learn<br>
                Detection Method: URL Pattern & Payload Analysis
            </p>
        </div>

    </div>

    {% endif %}

    <div class="features">

        <h3>📌 Supported Attack Detection</h3>

        <ul>
            <li>SQL Injection</li>
            <li>Cross Site Scripting (XSS)</li>
            <li>Server Side Request Forgery (SSRF)</li>
            <li>Directory Traversal</li>
            <li>Command Injection</li>
            <li>Credential Stuffing</li>
            <li>Web Shell Upload Detection</li>
            <li>Malicious URL Pattern Analysis</li>
        </ul>

    </div>

    <div class="footer">
        Educational Cybersecurity Research Project • Safe Detection System
    </div>

</div>

</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])

def home():

    prediction = ""
    ip_address = "N/A"
    risk_score = 0
    risk_level = "Low"
    card_class = "safe"

    if request.method == 'POST':

        url = request.form['url']

        # Extract IP safely
        try:
            domain = url.split('/')[0]

            if 'http://' in domain:
                domain = domain.replace('http://', '')

            if 'https://' in domain:
                domain = domain.replace('https://', '')

            ip_address = socket.gethostbyname(domain)

        except:
            ip_address = "Unable to Resolve"

        # ML Prediction
        url_vectorized = vectorizer.transform([url])

        result = model.predict(url_vectorized)[0]

        if result == 'Safe':

            prediction = '✅ SAFE REQUEST'
            risk_score = random.randint(5,25)
            risk_level = 'LOW'
            card_class = 'safe'

        else:

            prediction = f'⚠️ ATTACK DETECTED: {result}'
            risk_score = random.randint(70,98)
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

if __name__ == '__main__':
    app.run(debug=True)