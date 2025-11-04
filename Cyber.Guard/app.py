
from flask import Flask, request
import os, hashlib, shutil, requests, socket
from urllib.parse import urlparse
from datetime import datetime

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
QUARANTINE_DIR = "quarantine"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(QUARANTINE_DIR, exist_ok=True)

# === Embedded Malware Signatures ===
SIGNATURES = {
    "hashes": [
        "44D88612FEA8A8F36DE82E1278ABB02F",
        "E2FC714C4727EE9395F324CD2E7F331F"
    ],
    "patterns": [
        "EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
        "<script>malware_code()</script>",
        "ransomware_key",
        "trojan_exec"
    ],
    "malicious_domains": [
        "malicious.com", "malicous.com", "phishing-site.net", "evilserver.org"
    ],
    "suspicious_keywords": [
        "freegift", "win-money", "clickhere", "login-update",
        "claim-prize", "password-reset", "verify-account"
    ]
}

# === Core Functions ===
def compute_sha256(file_obj):
    sha = hashlib.sha256()
    file_obj.seek(0)
    while chunk := file_obj.read(8192):
        sha.update(chunk)
    file_obj.seek(0)
    return sha.hexdigest().upper()

def scan_file(file_obj):
    file_hash = compute_sha256(file_obj)
    if file_hash in SIGNATURES["hashes"]:
        return "🚨 Threat detected by HASH"
    try:
        content = file_obj.read().decode(errors="ignore")
        file_obj.seek(0)
        for pattern in SIGNATURES["patterns"]:
            if pattern in content:
                return "🚨 Threat detected by PATTERN"
    except Exception:
        pass
    return "✅ File appears safe"

def internet_available():
    try:
        socket.create_connection(("8.8.8.8", 53), 2)
        return True
    except OSError:
        return False

def scan_link_realtime(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    result = []

    for bad in SIGNATURES["malicious_domains"]:
        if bad in domain:
            return f"🚨 Known malicious domain detected: {domain}"

    try:
        socket.gethostbyname(domain)
    except socket.gaierror:
        return f"❌ Could not resolve domain: {domain}. DNS failure."

    if not internet_available():
        return "❌ No Internet connection detected."

    try:
        response = requests.get(url, timeout=6, allow_redirects=True, headers={'User-Agent': 'Mozilla/5.0'})
        html = response.text.lower()
        status = response.status_code

        if not url.startswith("https://"):
            result.append("⚠️ Website not using HTTPS")

        for word in SIGNATURES["suspicious_keywords"]:
            if word in html:
                result.append(f"⚠️ Suspicious keyword found: '{word}'")

        if status >= 400:
            result.append(f"⚠️ Website returned HTTP error: {status}")

        if not result:
            return f"✅ {domain} appears safe (HTTP {status})"
        else:
            return "<br>".join(result)

    except requests.exceptions.RequestException:
        return f"❌ Unable to connect to {domain}"

def quarantine_file(src_path, reason):
    filename = os.path.basename(src_path)
    dst = os.path.join(QUARANTINE_DIR, f"{filename}.quarantine")
    shutil.move(src_path, dst)
    with open(os.path.join(QUARANTINE_DIR, "metadata.log"), "a") as log:
        log.write(f"{datetime.now()} - {filename} quarantined ({reason})\n")

# === Splash Screen ===
@app.route("/")
def splash():
    return """
    <html>
    <head>
        <title>CyberGuard – Initializing...</title>
        <style>
            body {
                margin: 0;
                height: 100vh;
                background: radial-gradient(circle at center, #000428, #004e92);
                display: flex;
                justify-content: center;
                align-items: center;
                color: white;
                font-family: 'Segoe UI', sans-serif;
            }
            .splash {
                text-align: center;
                animation: fadeOut 1s ease 4s forwards;
            }
            @keyframes fadeOut {
                to { opacity: 0; transform: scale(1.1); }
            }
            .shield {
                font-size: 100px;
                animation: spin 4s linear infinite;
                display: inline-block;
            }
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
            .title {
                font-size: 36px;
                margin-top: 20px;
            }
            .subtitle {
                color: #ccc;
                margin-top: 5px;
                font-size: 16px;
            }
        </style>
        <script>
            setTimeout(() => {
                window.location.href = '/dashboard';
            }, 5000);
        </script>
    </head>
    <body>
        <div class="splash">
            <div class="shield">🛡️</div>
            <div class="title">CyberGuard</div>
        </div>
    </body>
    </html>
    """

# === Dashboard ===
@app.route("/dashboard")
def dashboard():
    return """
    <html>
    <head>
        <title>CyberGuard Antivirus Dashboard</title>
        <style>
            body {
                font-family: 'Segoe UI', sans-serif;
                background: radial-gradient(circle at top, #000428, #004e92);
                color: white;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
            }
            .card {
                background: white;
                color: #1b2735;
                border-radius: 20px;
                padding: 40px;
                box-shadow: 0 8px 30px rgba(0,0,0,0.3);
                width: 420px;
                text-align: center;
                animation: fadeIn 1s ease-in;
            }
            @keyframes fadeIn { from {opacity: 0;} to {opacity: 1;} }
            h2 { color: #004e92; margin-bottom: 10px; }
            input[type=file], input[type=text] {
                width: 90%;
                padding: 10px;
                margin-top: 10px;
                border-radius: 8px;
                border: 1px solid #ccc;
                font-size: 14px;
            }
            input[type=submit] {
                background: #004e92;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 8px;
                margin-top: 15px;
                cursor: pointer;
                font-size: 16px;
                transition: 0.3s;
            }
            input[type=submit]:hover { background: #000428; }
            hr { border: none; border-top: 1px solid #eee; margin: 25px 0; }
            #overlay {
                display: none;
                position: fixed;
                top: 0; left: 0;
                width: 100%; height: 100%;
                background: rgba(0,0,0,0.85);
                z-index: 9999;
                justify-content: center;
                align-items: center;
                color: white;
                font-size: 22px;
                flex-direction: column;
            }
            .loader {
                border: 6px solid #f3f3f3;
                border-top: 6px solid #004e92;
                border-radius: 50%;
                width: 70px;
                height: 70px;
                animation: spin 1s linear infinite;
                margin-bottom: 20px;
            }
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
        </style>
        <script>
            function showOverlay(){
                document.getElementById('overlay').style.display='flex';
            }
        </script>
    </head>
    <body>
        <div id="overlay">
            <div class="loader"></div>
            <p>Scanning in progress... Please wait</p>
        </div>

        <div class="card">
            <h2>🛡️ CyberGuard</h2>
            <p>Advanced Threat Detection System</p>

            <form action="/scan" method="post" enctype="multipart/form-data" onsubmit="showOverlay()">
                <h3>📁 File Scanner</h3>
                <input type="file" name="file" required><br>
                <input type="submit" value="Scan File">
            </form>

            <hr>

            <form action="/scan" method="post" onsubmit="showOverlay()">
                <h3>🌐 Website Scanner</h3>
                <input type="text" name="url" placeholder="Enter full URL (https://...)" required><br>
                <input type="submit" value="Scan Website">
            </form>
        </div>
    </body>
    </html>
    """

# === Result Page ===
@app.route("/scan", methods=["POST"])
def scan():
    result = ""
    quarantined = False
    filename = ""

    if "file" in request.files and request.files["file"].filename:
        file = request.files["file"]
        filename = file.filename
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)

        with open(file_path, "rb") as f:
            result = scan_file(f)

        if "🚨" in result:
            quarantine_file(file_path, reason=result)
            quarantined = True
        else:
            os.remove(file_path)

    elif "url" in request.form and request.form["url"].strip():
        url = request.form["url"].strip()
        filename = url
        result = scan_link_realtime(url)

    color = "green" if "✅" in result else "red" if "🚨" in result else "orange"
    icon = "✅" if "✅" in result else "🚨" if "🚨" in result else "⚠️"
    q_text = "<p style='color:red;'>🧩 File quarantined for safety.</p>" if quarantined else ""

    return f"""
    <html>
    <head>
        <title>CyberGuard Scan Result</title>
        <style>
            body {{
                font-family: 'Segoe UI', sans-serif;
                background: linear-gradient(120deg, #0f2027, #203a43, #2c5364);
                color: white;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
            }}
            .result {{
                background: white;
                color: #1b2735;
                padding: 40px;
                border-radius: 20px;
                box-shadow: 0 8px 30px rgba(0,0,0,0.3);
                text-align: center;
                width: 500px;
                animation: slideUp 0.8s ease;
            }}
            @keyframes slideUp {{
                from {{transform: translateY(30px); opacity:0;}}
                to {{transform: translateY(0); opacity:1;}}
            }}
            .status {{
                color: {color};
                font-size: 20px;
                margin: 10px 0;
            }}
            a {{
                color: #004e92;
                text-decoration: none;
                font-weight: bold;
            }}
            a:hover {{ text-decoration: underline; }}
        </style>
    </head>
    <body>
        <div class="result">
            <h2>🧾 CyberGuard Scan Report</h2>
            <h3>{filename}</h3>
            <p class="status">{icon} {result}</p>
            {q_text}
            <br><br>
            <a href="/dashboard">⬅ Back to Dashboard</a>
        </div>
    </body>
    </html>
    """

if __name__ == "__main__":
    app.run(debug=True)
