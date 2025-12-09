import json
import os
from html import escape

BASE = "reports"

# ---------------- UTIL ----------------
def load_json(path):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            try:
                return json.load(f)
            except:
                return None
    return None

def load_text(path):
    if os.path.exists(path):
        return open(path, "r", encoding="utf-8", errors="ignore").read()
    return None

def section(title, content):
    return f"""
    <div class="section">
        <h2>{title}</h2>
        {content}
    </div>
    """

# ---------------- CI STATUS ----------------
def parse_ci_status():
    path = f"{BASE}/ci-status/status.json"
    data = load_json(path)

    if not data:
        return "<p>⚠️ Aucune information CI trouvée.</p>"

    def icon(v):
        return "✔️" if v == "OK" else "❌"

    html = "<table><tr><th>Étape CI</th><th>Statut</th></tr>"
    html += f"<tr><td>Compilation Maven</td><td>{icon(data.get('compile'))}</td></tr>"
    html += f"<tr><td>Tests unitaires</td><td>{icon(data.get('tests'))}</td></tr>"
    html += f"<tr><td>Build JAR</td><td>{icon(data.get('artifact'))}</td></tr>"
    html += f"<tr><td>Cache Maven</td><td>{icon(data.get('cache'))}</td></tr>"
    html += f"<tr><td>Nettoyage Runner</td><td>{icon(data.get('cleanup'))}</td></tr>"
    html += "</table>"
    return html

# ---------------- SEMGREP ----------------
def parse_semgrep():
    path = f"{BASE}/semgrep-report/semgrep.json"
    data = load_json(path)
    if not data:
        return "<p>Rapport introuvable.</p>"

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
    path = f"{BASE}/trufflehog-report/trufflehog.json"
    data = load_json(path)
    if data is None:
        return "<p>Rapport introuvable.</p>"
    if isinstance(data, list) and len(data) == 0:
        return "<p>Aucun secret détecté ✔</p>"
    return "<p>⚠️ Des secrets ont été détectés (détails masqués).</p>"

# ---------------- SBOM ----------------
def parse_sbom():
    path = f"{BASE}/sbom-report/sbom.json"
    data = load_json(path)
    if not data:
        return "<p>Rapport introuvable.</p>"

    comps = data.get("artifacts", [])
    html = f"<p><b>Composants détectés :</b> {len(comps)}</p>"

    html += "<table><tr><th>Nom</th><th>Version</th><th>Type</th></tr>"
    for c in comps:
        html += f"<tr><td>{escape(c['name'])}</td><td>{c.get('version','?')}</td><td>{c.get('type','?')}</td></tr>"
    html += "</table>"

    return html

# ---------------- TRIVY ----------------
def parse_trivy():
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
        html += f"<tr><td>{v['VulnerabilityID']}</td><td>{v.get('PkgName')}</td><td>{v.get('InstalledVersion')}</td><td>{v.get('FixedVersion')}</td><td>{v['Severity']}</td></tr>"
    html += "</table>"
    return html

# ---------------- NIKTO ----------------
nikto_mapping = [
    ("directory indexing", "Le serveur liste les fichiers d’un dossier.", "Désactiver dans Apache : Options -Indexes"),
    ("x-frame-options", "Protection clickjacking absente.", "Ajouter Header X-Frame-Options DENY"),
    ("wildcard", "Wildcard dangereux dans une policy XML.", "Restreindre les domaines, retirer le *."),
    ("login", "Page admin accessible publiquement.", "Protéger via firewall + MFA."),
    ("alert", "Injection XSS détectée.", "Échapper les entrées utilisateur."),
]

def parse_nikto():
    path = f"{BASE}/nikto-report/nikto.txt"
    txt = load_text(path)
    if not txt:
        return "<p>Rapport introuvable.</p>"

    rows = []
    for line in txt.splitlines():
        l = line.lower()
        for key, exp, fix in nikto_mapping:
            if key in l:
                rows.append((escape(line), exp, fix))

    if not rows:
        return "<p>Aucun problème critique détecté ✔</p>"

    html = "<table><tr><th>Entrée</th><th>Explication</th><th>Correctif</th></tr>"
    for log, exp, fix in rows:
        html += f"<tr><td>{log}</td><td>{exp}</td><td>{fix}</td></tr>"
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
th, td { padding:8px; border-bottom:1px solid #ddd; vertical-align: top; }
th { background:#e9f2ff; }
</style>
</head>
<body>
<h1>🔐 DevSecOps – Security Dashboard</h1>
"""

html += section("⚙️ CI - Compilation & Tests", parse_ci_status())
html += section("🔍 SAST - Semgrep", parse_semgrep())
html += section("🧩 SCA - Trivy FS", "<p>Analyse réalisée via Trivy filesystem.</p>")
html += section("🔒 Secrets Scan - TruffleHog", parse_trufflehog())
html += section("📦 SBOM - Syft", parse_sbom())
html += section("🐳 Docker Scan - Trivy", parse_trivy())
html += section("🌐 DAST - Nikto (Explications + Correctifs)", parse_nikto())
html += section("🔎 Code Quality - Qodana", "<p>Analyse effectuée dans Qodana Cloud.</p>")

html += "</body></html>"

with open("security-dashboard.html", "w", encoding="utf-8") as f:
    f.write(html)

print("Dashboard généré avec succès ✔ (version PRO)")
