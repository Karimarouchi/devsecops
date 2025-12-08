import json
import os
from datetime import datetime

BASE = "reports"

def load_json(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except:
        return None


def section(title, content):
    return f"""
    <h2>{title}</h2>
    <div>{content}</div>
    <hr>
    """


#---------------------- SEMGREP ----------------------
def parse_semgrep():
    path = f"{BASE}/semgrep-report/semgrep.json"
    data = load_json(path)
    if not data or "results" not in data:
        return "<p>Aucun résultat.</p>"

    html = "<ul>"
    for r in data["results"]:
        html += f"<li><b>{r.get('check_id')}</b> — {r.get('path')}</li>"
    html += "</ul>"
    return html


#---------------------- TRIVY SCA ----------------------
def parse_sca():
    path = f"{BASE}/sca-report/trivy-sca.json"
    data = load_json(path)
    if not data:
        return "<p>Rapport introuvable.</p>"

    vulns = []
    for result in data.get("Results", []):
        for v in result.get("Vulnerabilities", []):
            vulns.append(v)

    if not vulns:
        return "<p>Aucune vulnérabilité trouvée ✔</p>"

    html = "<table border='1'><tr><th>CVE</th><th>Package</th><th>Version</th><th>Fix</th><th>Sévérité</th></tr>"
    for v in vulns:
        html += f"<tr><td>{v['VulnerabilityID']}</td><td>{v.get('PkgName')}</td><td>{v.get('InstalledVersion')}</td><td>{v.get('FixedVersion')}</td><td>{v['Severity']}</td></tr>"
    html += "</table>"
    return html


#---------------------- TRUFFLEHOG ----------------------
def parse_secrets():
    path = f"{BASE}/trufflehog-report/trufflehog.json"
    data = load_json(path)
    if not data:
        return "<p>Aucun secret détecté ✔</p>"
    return f"<pre>{json.dumps(data, indent=2)}</pre>"


#---------------------- SBOM ----------------------
def parse_sbom():
    path = f"{BASE}/sbom-report/sbom.json"
    data = load_json(path)
    if not data:
        return "<p>SBOM introuvable.</p>"
    return "<p>SBOM généré ✔</p>"


#---------------------- TRIVY DOCKER ----------------------
def parse_trivy_docker():
    path = f"{BASE}/trivy-report/trivy.json"
    data = load_json(path)
    if not data:
        return "<p>Aucun rapport Docker.</p>"
    return "<pre>Vulnérabilités Docker trouvées ✔</pre>"


#---------------------- NIKTO ----------------------
def parse_nikto():
    path = f"{BASE}/nikto-report/nikto.txt"
    if not os.path.exists(path):
        return "<p>Rapport Nikto introuvable.</p>"
    with open(path, "r") as f:
        content = f.read()
    return f"<pre>{content}</pre>"


#---------------------- GENERATE HTML ----------------------
html = f"""
<html>
<head>
<title>Security Dashboard</title>
<style>
body {{ font-family: Arial; padding: 20px; }}
h1 {{ background: #222; color: white; padding: 10px; }}
h2 {{ color: #1F6FEB; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ccc; padding: 8px; }}
</style>
</head>
<body>

<h1>🔐 Security Dashboard – {datetime.now().strftime("%Y-%m-%d %H:%M")}</h1>

{section("🔍 SAST – Semgrep", parse_semgrep())}
{section("🧩 SCA – Trivy FS", parse_sca())}
{section("🔒 Secrets – TruffleHog", parse_secrets())}
{section("📦 SBOM – Syft", parse_sbom())}
{section("🐳 Docker Scan – Trivy", parse_trivy_docker())}
{section("🌐 DAST – Nikto", parse_nikto())}

</body>
</html>
"""

with open("security-dashboard.html", "w") as f:
    f.write(html)

print("Dashboard generated ✔")
