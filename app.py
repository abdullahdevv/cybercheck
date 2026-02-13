from flask import Flask, request, render_template
import requests
from urllib.parse import urlparse
from datetime import datetime, timezone
import socket, ssl

app = Flask(__name__)

RECOMMENDED = [
    ("Strict-Transport-Security", "Enforces HTTPS (HSTS) to prevent downgrade attacks."),
    ("Content-Security-Policy", "Helps mitigate XSS and content injection."),
    ("X-Frame-Options", "Protects against clickjacking."),
    ("X-Content-Type-Options", "Prevents MIME sniffing."),
    ("Referrer-Policy", "Controls referrer information leakage."),
    ("Permissions-Policy", "Restricts powerful browser features."),
]

DONATE_URL = "https://buymeacoffee.com/cyberguard"

def normalize_url(u: str) -> str:
    u = u.strip()
    if not u.startswith(("http://", "https://")):
        u = "https://" + u
    return u

def get_cert_expiry(hostname: str, port: int = 443, timeout: int = 5):
    """Passive SSL cert expiry check. Returns (days_left, not_after_str) or (None, None)."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        not_after = cert.get("notAfter")
        if not not_after:
            return None, None
        # Example format: 'Jun 15 12:00:00 2026 GMT'
        dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (dt - datetime.now(timezone.utc)).days
        return days_left, not_after
    except Exception:
        return None, None

def grade_from_score(score: int) -> str:
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 55: return "C"
    return "D"

@app.route("/", methods=["GET", "POST"])
def index():
    result = None

    if request.method == "POST":
        raw = request.form["url"]
        url = normalize_url(raw)

        headers_found = {}
        missing = []
        tips = []
        error = None
        redirects = []
        score = 0

        try:
            r = requests.get(url, timeout=12, allow_redirects=True, headers={"User-Agent": "CyberCheck/1.0"})
            final_url = r.url  # بعد الريدايركت
            parsed = urlparse(final_url)
            hostname = parsed.hostname or ""
            https = (parsed.scheme == "https")

            # Redirect chain
            redirects = [resp.url for resp in r.history] + [r.url] if r.history else [r.url]

            # HTTPS points
            if https:
                score += 20
            else:
                tips.append("Your site is not using HTTPS. Enable TLS/SSL and redirect HTTP → HTTPS.")

            # Header checks (80 points total)
            per_header = 80 // len(RECOMMENDED)
            for h, why in RECOMMENDED:
                if h in r.headers:
                    headers_found[h] = r.headers.get(h)
                    score += per_header
                else:
                    missing.append({"name": h, "why": why})

            # Cert expiry (optional bonus/penalty signals - لا يغير السكور كثير)
            cert_days, cert_not_after = (None, None)
            if https and hostname:
                cert_days, cert_not_after = get_cert_expiry(hostname)
                if cert_days is not None:
                    if cert_days < 0:
                        tips.append("SSL certificate appears expired. Renew it ASAP.")
                    elif cert_days <= 14:
                        tips.append(f"SSL certificate expires soon ({cert_days} days). Plan renewal.")
                else:
                    tips.append("Could not read SSL certificate expiry (might be blocked or non-standard setup).")

            # Clamp score
            score = max(0, min(100, score))
            grade = grade_from_score(score)

            # Extra helpful tips based on missing
            if any(m["name"] == "Content-Security-Policy" for m in missing):
                tips.append("Consider adding a strict Content-Security-Policy (start with report-only if needed).")
            if any(m["name"] == "Strict-Transport-Security" for m in missing) and https:
                tips.append("Enable HSTS to enforce HTTPS after first visit.")

            if not headers_found:
                headers_found = {"(none found)": "No recommended security headers detected."}

            result = {
                "input": raw,
                "final_url": final_url,
                "https": https,
                "headers": headers_found,
                "missing": missing,
                "tips": tips,
                "score": score,
                "grade": grade,
                "redirects": redirects,
                "cert_days": cert_days,
                "cert_not_after": cert_not_after,
                "error": error,
            }

        except Exception as e:
            result = {
                "input": raw,
                "final_url": url,
                "https": False,
                "headers": {},
                "missing": [],
                "tips": [],
                "score": 0,
                "grade": "D",
                "redirects": [],
                "cert_days": None,
                "cert_not_after": None,
                "error": str(e),
            }

    return render_template(
        "index.html",
        result=result,
        donate_url=DONATE_URL,
        year=datetime.now().year
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
