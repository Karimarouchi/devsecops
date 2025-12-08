import json
import os
from html import escape

BASE = "reports"

# ---------------- COMMON UTIL ----------------
def load_json(path):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return json.load(f)
        except:
            return None
    return None

def section(title, content):
    return f"""
    <div class="section">
        <h2>{title}</h2>
        {content}
    </div>
    """

# ---------------- SEMGREP ----------------
def parse_semgrep():
    path = f"{BASE}/semgrep-report/semgrep.json"
    data = load_json(path)

    if not data:
        return "<p>Rapport introuvable.</p>"

    # Erreur Semgrep (patterns invalides)
    if data.get("errors"):
        msg = escape(data["errors"][0]["message"])
        return f"<div class='error-box'><b>Erreur Semgrep :</b><br>{msg}</div>"

    results = data.get("results", [])
    if not results:
        return "<p>Aucun problème détecté ✔</p>"

    html = "<table><tr><th>Fichier</th><th>Ligne</th><th>Message</th><th>Sévérité</th></tr>"
    for r in results:
        html += f"<tr><td>{escape(r['path'])}</td><td>{r['start']['line']}</td><td>{escape(r['extra']['message'])}</td><td>{r['extra'].get('severity')}</td></tr>"
    html += "</table>"

    return html

# ---------------- TRUFFLEHOG ----------------
def parse_trufflehog():
    path1 = f"{BASE}/trufflehog-report/trufflehog.json"
    path2 = f"{BASE}/trufflehog.json"

    data = load_json(path1) or load_json(path2)

    if data is None:
        return "<p>Rapport introuvable.</p>"

    if isinstance(data, list) and len(data) == 0:
        return "<p>Aucun secret détecté ✔</p>"

    return "<p>Secrets détectés (non affichés pour sécurité).</p>"

# ---------------- DEPENDENCY CHECK ----------------
def parse_dependency():
    path1 = f"{BASE}/dependency-report/dependency-check-report.html"
    path2 = f"{BASE}/dep-report/dependency-check-report.html"

    if os.path.exists(path1) or os.path.exists(path2):
        return "<p>Rapport disponible : dependency-check-report.html</p>"

    return "<p>Rapport introuvable.</p>"

# ---------------- SBOM ----------------
def parse_sbom():
    path = f"{BASE}/sbom-report/sbom.json"
    data = load_json(path)
    if not data:
        return "<p>Rapport introuvable.</p>"

    components = data.get("artifacts", [])
    html = f"<p><b>Composants détectés :</b> {len(components)}</p>"

    html += "<table><tr><th>Nom</th><th>Version</th><th>Type</th></tr>"
    for comp in components:
        html += f"<tr><td>{escape(comp['name'])}</td><td>{comp.get('version','?')}</td><td>{comp.get('type','?')}</td></tr>"
    html += "</table>"

    return html

# ---------------- TRIVY ----------------
def parse_trivy():
    path = f"{BASE}/trivy-report/trivy.json"
    data = load_json(path)
    if not data:
        return "<p>Rapport introuvable.</p>"

    results = []
    for r in data.get("Results", []):
        for v in r.get("Vulnerabilities", []):
            results.append(v)

    if not results:
        return "<p>Aucune vulnérabilité trouvée ✔</p>"

    html = "<table><tr><th>CVE</th><th>Package</th><th>Version</th><th>Fix</th><th>Sévérité</th></tr>"
    for v in results:
        html += f"<tr><td>{v['VulnerabilityID']}</td><td>{v.get('PkgName','?')}</td><td>{v.get('InstalledVersion')}</td><td>{v.get('FixedVersion')}</td><td>{v['Severity']}</td></tr>"
    html += "</table>"

    return html

# ---------------- NIKTO (lisible & propre) ----------------
def parse_nikto():
    path = f"{BASE}/nikto-report/nikto.txt"

    if not os.path.exists(path):
        return "<p>Rapport introuvable.</p>"

    lines = open(path, "r", encoding="utf-8", errors="ignore").read().splitlines()

    # On extrait seulement les findings qui commencent par "+ "
    findings = [l[2:] for l in lines if l.startswith("+ ")]

    if not findings:
        return "<p>Aucune vulnérabilité trouvée ✔</p>"

    html = "<table><tr><th>Vulnérabilité détectée</th></tr>"
    for f in findings:
        html += f"<tr><td>{escape(f)}</td></tr>"
    html += "</table>"

    return html

# ---------------- BUILD HTML ----------------
html = """
<html>
<head>
<title>Security Dashboard</title>

<style>
body { font-family: Arial; background:#f9fafc; padding:20px; }
.section { background:white; padding:20px; margin-bottom:20px; border-radius:12px; box-shadow:0 2px 6px #00000015; }
table { width:100%; border-collapse:collapse; }
th, td { padding:8px; border-bottom:1px solid #ddd; }
th { background:#e9f2ff; }
.error-box { background:#ffe5e5; border-left:5px solid #ff0000; padding:10px; border-radius:8px; }
</style>

</head>
<body>

<h1>🔐 DevSecOps – Security Dashboard</h1>
"""

html += section("🔍 SAST - Semgrep", parse_semgrep())
html += section("🧩 SCA - Dependency Check", parse_dependency())
html += section("🔒 Secrets Scan - TruffleHog", parse_trufflehog())
html += section("📦 SBOM - Syft", parse_sbom())
html += section("🐳 Docker Scan - Trivy", parse_trivy())
html += section("🌐 DAST - Nikto", parse_nikto())
html += section("🔎 Code Quality - Qodana", "<p>Analyse Qodana exécutée dans Qodana Cloud.</p>")

html += "</body></html>"

with open("security-dashboard.html", "w", encoding="utf-8") as f:
    f.write(html)

print("Dashboard généré avec succès ✔")
