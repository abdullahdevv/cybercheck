from flask import Flask, request, render_template
import requests
from urllib.parse import urlparse
from datetime import datetime

app = Flask(__name__)

RECOMMENDED = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

DONATE_URL = "https://buymeacoffee.com/cyberguard"

def normalize_url(u: str) -> str:
    u = u.strip()
    if not u.startswith(("http://", "https://")):
        u = "https://" + u
    return u

@app.route("/", methods=["GET", "POST"])
def index():
    result = None

    if request.method == "POST":
        url = normalize_url(request.form["url"])
        parsed = urlparse(url)
        https = (parsed.scheme == "https")

        headers = {}
        missing = RECOMMENDED.copy()
        error = None
        score = 0

        try:
            r = requests.get(url, timeout=10, allow_redirects=True)

            # نقاط HTTPS
            if https:
                score += 20

            # فحص الهيدرز
            for h in RECOMMENDED:
                if h in r.headers:
                    headers[h] = r.headers.get(h)
                    if h in missing:
                        missing.remove(h)

            # نقاط الهيدرز (80%)
            score += (len(headers) * 80) // len(RECOMMENDED)

            if not headers:
                headers = {"(none found)": "No recommended security headers detected"}

        except Exception as e:
            error = str(e)

        result = {
            "url": url,
            "https": https,
            "headers": headers,
            "missing": missing,
            "error": error,
            "score": score
        }

    return render_template(
        "index.html",
        result=result,
        donate_url=DONATE_URL,
        year=datetime.now().year
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
