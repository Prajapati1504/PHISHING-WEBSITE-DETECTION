import os
import re
import joblib
from flask import Flask, request, render_template_string
from urllib.parse import urlparse
from feature_extraction import extract_features

# ---------------- LOAD MODEL ----------------
model = joblib.load('rf_phishing_model.pkl')
app = Flask(__name__)

# ---------------- HTML UI ----------------
HTML = '''
<h2>Phishing URL Detection (Adversarially Robust)</h2>
<form method="post">
<input name="url" size="80" placeholder="Enter URL here" required>
<input type="submit">
</form>
{% if result %}
<h3>{{ result }}</h3>
{% endif %}
'''

# ---------------- SAFE URL PARSER (ONLY ADDITION) ----------------
def safe_urlparse(url):
    try:
        if not re.match(r'^[a-zA-Z]+://', url):
            url = 'http://' + url
        return urlparse(url)
    except ValueError:
        return None


# ---------------- RULE-BASED DEFENSE (50 RULES) ----------------
def rule_based_check(url):
    url = url.lower().strip()

    parsed = safe_urlparse(url)
    if parsed is None:
        return True  # malformed URL = phishing

    domain = parsed.netloc
    score = 0

    brands = [
        'google','facebook','paypal','amazon','apple','microsoft',
        'netflix','instagram','bank','upi','whatsapp'
    ]

    keywords = [
        'login','verify','secure','update','confirm','reset',
        'billing','account','support','authentication','alert',
        'suspend','validate','signin','payment'
    ]

    risky_tlds = [
        '.xyz','.top','.tk','.ml','.cf','.ga','.gq',
        '.work','.click','.support','.info'
    ]

    # -------- RULES 1–25 --------
    if any(b in url for b in brands): score += 2
    if any(k in url for k in keywords): score += 2
    if any(tld in domain for tld in risky_tlds): score += 3
    if re.search(r'\b\d{1,3}(\.\d{1,3}){3}\b', domain): score += 3
    if len(url) > 75: score += 1
    if len(url) > 120: score += 2
    if domain.count('.') >= 4: score += 2
    if domain.count('-') >= 2: score += 1
    if '@' in url: score += 3
    if url.count('//') > 1: score += 2
    if parsed.scheme == 'http': score += 1
    if 'xn--' in domain: score += 3
    if re.search(r'[a-z]{10,}', domain): score += 1
    if re.search(r'\d{3,}', domain): score += 1
    if any(s in domain for s in ['bit.ly','tinyurl','t.co','is.gd','goo.gl']): score += 3
    if any(p in parsed.path for p in ['/login','/verify','/secure','/update','/account']): score += 1
    if parsed.path.endswith(('.exe','.zip','.html','.php')): score += 1
    if parsed.path.count('.') > 2: score += 1
    if '%' in url: score += 1
    if parsed.port not in (None, 80, 443): score += 2
    if re.search(r'[\w\.-]+@[\w\.-]+', url): score += 3
    if any(h in domain for h in ['000webhost','github.io','herokuapp','vercel.app']): score += 2
    if 'redirect' in url or 'next=' in url: score += 1
    if any(b in domain for b in brands) and not domain.endswith(('.com','.org','.net')): score += 2
    if url.count('=') >= 3: score += 1
    if len(set(domain)) / max(len(domain), 1) > 0.7: score += 1

    # -------- RULES 26–50 --------
    parts = domain.split('.')
    subdomain = parts[0]
    root_domain = parts[-2] if len(parts) >= 2 else domain

    if any(b in subdomain for b in brands) and not any(b in root_domain for b in brands): score += 1
    if any(b in parsed.path for b in brands): score += 1
    if sum(1 for b in brands if b in url) >= 2: score += 2
    if re.search(r'(google|paypal|amazon|apple)\d+', url): score += 2
    if re.search(r'g00gle|faceb00k|paypa1|micros0ft', url): score += 3
    if re.search(r'(login|verify|secure).*\1', url): score += 1
    if '--' in url or '__' in url: score += 1
    if re.search(r'[-_\.]{3,}', url): score += 1
    if parsed.path.count('/') >= 5: score += 1
    if len(parsed.path) > 60: score += 1
    if re.search(r'[а-яА-Я]', url): score += 3
    if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', url): score += 2
    if re.search(r'[a-f0-9]{16,}', url): score += 1
    if '%25' in url: score += 2
    if url.count('%') > 5: score += 1
    if any(c in domain for c in ['s3','blob','storage.googleapis']): score += 2
    if any(cdn in domain for cdn in ['cloudfront','akamai','fastly']): score += 2
    if any(dns in domain for dns in ['duckdns','no-ip','dynu']): score += 3
    if url.count('http') > 1: score += 2
    if any(h in domain for h in ['cpanel','webhost','hosting']): score += 1
    if re.search(r'session|token|sid=', url): score += 2
    if 'client_id=' in url or 'redirect_uri=' in url: score += 2
    if 'captcha' in url and not domain.endswith('.google.com'): score += 2
    if 'password' in url and 'reset' in url: score += 2
    if any(u in url for u in ['urgent','immediately','action-required']): score += 1

    return score >= 6


# ---------------- FLASK ROUTE ----------------
@app.route('/', methods=['GET', 'POST'])
def index():
    result = None

    if request.method == 'POST':
        url = request.form['url'].strip()

        if rule_based_check(url):
            result = "Phishing Website (High-Risk Pattern Detected)"
        else:
            features = extract_features(url)
            pred = model.predict([features])[0]
            result = "Phishing Website" if pred == 1 else "Legitimate Website"

        # -------- LOGGING --------
        if not os.path.exists("runtime_results.csv"):
            with open("runtime_results.csv", "w") as f:
                f.write("Prediction\n")

        with open("runtime_results.csv", "a") as f:
            f.write(result + "\n")

    return render_template_string(HTML, result=result)


# ---------------- RUN SERVER ----------------
if __name__ == '__main__':
    app.run(debug=True)
