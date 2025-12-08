import json
import os
from html import escape

BASE = "reports"

def load_json(path):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            try:
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

    if data.get("errors"):
        msg = escape(data["errors"][0]["message"])
        return f"<p><b>Erreur Semgrep :</b> {msg}</p>"

    results = data.get("results", [])
    if not results:
        return "<p>Aucun problème détecté ✔</p>"

    html = "<table><tr><th>Fichier</th><th>Ligne</th><th>Message</th><th>Sévérité</th></tr>"
    for r in results:
        html += f"<tr><td>{escape(r['path'])}</td><td>{r['start']['line']}</td><td>{escape(r['extra']['message'])}</td><td>{r['extra'].get('severity')}</td></tr>"
    html += "</table>"
    return html


# ---------------- SCA NEW (TRIVY FS) ----------------
def parse_sca_trivy():
    path = f"{BASE}/sca-report/trivy-sca.json"
    data = load_json(path)

    if not data:
        return "<p>Rapport introuvable.</p>"

    vulnerabilities = []

    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            vulnerabilities.append(vuln)

    if not vulnerabilities:
        return "<p>Aucune vulnérabilité trouvée ✔</p>"

    html = "<table><tr><th>CVE</th><th>Package</th><th>Version</th><th>Fix</th><th>Sévérité</th></tr>"
    for v in vulnerabilities:
        html += f"""
        <tr>
            <td>{escape(v['VulnerabilityID'])}</td>
            <td>{escape(v.get('PkgName', '?'))}</td>
            <td>{escape(v.get('InstalledVersion', '?'))}</td>
            <td>{escape(v.get('FixedVersion', '?'))}</td>
            <td>{escape(v.get('Severity', '?'))}</td>
        </tr>
        """
    html += "</table>"
    return html


# ---------------- TRUFFLEHOG ----------------
def parse_trufflehog():
    path = f"{BASE}/trufflehog-report/trufflehog.json"
    data = load_json(path)

    if data is None:
        return "<p>Rapport introuvable.</p>"

    if isinstance(data, list) and len(data) == 0:
        return "<p>Aucun secret détecté ✔</p>"

    return "<p>Secrets détectés (non affichés ici pour sécurité).</p>"


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


# ---------------- TRIVY DOCKER ----------------
def parse_trivy_docker():
    path = f"{BASE}/trivy-report/trivy.json"
    data = load_json(path)
    if not data:
        return "<p>Rapport introuvable.</p>"

    vulns = []
    for r in data.get("Results", []):
        for v in r.get("Vulnerabilities", []):
            vulns.append(v)

    if not vulns:
        return "<p>Aucune vulnérabilité trouvée ✔</p>"

    html = "<table><tr><th>CVE</th><th>Package</th><th>Version</th><th>Fix</th><th>Sévérité</th></tr>"
    for v in vulns:
        html += f"<tr><td>{v['VulnerabilityID']}</td><td>{v.get('PkgName','?')}</td><td>{v.get('InstalledVersion')}</td><td>{v.get('FixedVersion')}</td><td>{v['Severity']}</td></tr>"
    html += "</table>"
    return html


# ---------------- NIKTO ----------------
def parse_nikto():
    path = f"{BASE}/nikto-report/nikto.txt"
    if not os.path.exists(path):
        return "<p>Rapport introuvable.</p>"

    raw = open(path, "r", encoding="utf-8", errors="ignore").read()
    lines = raw.split("\n")

    findings = []

    for line in lines:
        line = line.strip()

        # On ne garde que les vraies vulnérabilités / issues
        if line.startswith("+") and ":" in line:
            try:
                parts = line[1:].split(":", 1)
                endpoint = parts[0].strip()
                issue = parts[1].strip()
                findings.append((endpoint, issue))
            except:
                continue

    if not findings:
        return "<p>Aucune anomalie détectée ✔</p>"

    # Construction d’un tableau propre
    html = "<table><tr><th>Chemin</th><th>Problème détecté</th></tr>"
    for endpoint, issue in findings:
        html += f"<tr><td>{escape(endpoint)}</td><td>{escape(issue)}</td></tr>"
    html += "</table>"

    return html


# ---------------- HTML BUILD ----------------
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
</style>
</head>
<body>

<h1>🔐 DevSecOps – Security Dashboard</h1>
"""

html += section("🔍 SAST - Semgrep", parse_semgrep())
html += section("🧩 SCA - Trivy FS", parse_sca_trivy())
html += section("🔒 Secrets Scan - TruffleHog", parse_trufflehog())
html += section("📦 SBOM - Syft", parse_sbom())
html += section("🐳 Docker Scan - Trivy", parse_trivy_docker())
html += section("🌐 DAST - Nikto", parse_nikto())
html += section("🔎 Code Quality - Qodana", "<p>Analyse Qodana exécutée dans Qodana Cloud.</p>")

html += "</body></html>"

with open("security-dashboard.html", "w", encoding="utf-8") as f:
    f.write(html)

print("Dashboard généré avec succès ✔")
