import os
import json
from pathlib import Path

# -----------------------------------------------------
# Helper: read a file safely
# -----------------------------------------------------
def read_file(path):
    if not os.path.exists(path):
        print(f"⚠️  Fichier introuvable : {path}")
        return None

    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        print(f"❌ Erreur lecture fichier {path}: {e}")
        return None


# -----------------------------------------------------
# Vérification des rapports
# -----------------------------------------------------

reports = {
    "semgrep": "semgrep-report/semgrep.json",
    "sca": "dependency-report/dependency-check-report.html",
    "trufflehog": "trufflehog-report/trufflehog.json",
    "sbom": "sbom-report/sbom.json",
    "trivy": "trivy-report/trivy.json",
    "nikto": "nikto-report/nikto.txt"
}

loaded_reports = {}

print("\n📌 Vérification des rapports...\n")

for key, path in reports.items():
    if os.path.exists(path):
        print(f"✔️  {key.upper()} trouvé : {path}")
        loaded_reports[key] = read_file(path)
    else:
        print(f"❌ {key.upper()} manquant : {path}")
        loaded_reports[key] = None


# -----------------------------------------------------
# Templates HTML simples
# -----------------------------------------------------

def html_section(title, content):
    if not content:
        content_html = "<p style='color:#999;'>Rapport non trouvé.</p>"
    else:
        content_html = f"<pre style='background:#f4f4f4;padding:10px;border-radius:6px;'>{content[:3000]}</pre>"

    return f"""
    <section style="padding:20px;border-bottom:1px solid #ddd;">
        <h2>{title}</h2>
        {content_html}
    </section>
    """


# -----------------------------------------------------
# Construction Dashboard HTML
# -----------------------------------------------------

html = """
<html>
<head>
    <meta charset="utf-8"/>
    <title>DevSecOps - Security Dashboard</title>
    <style>
        body { font-family: Arial; background:#fafafa; }
        h1 { background:#111; color:white; padding:15px; }
        h2 { color:#333; }
    </style>
</head>
<body>
<h1>🔐 DevSecOps – Security Dashboard</h1>
"""

html += html_section("🔍 SAST - Semgrep", loaded_reports["semgrep"])
html += html_section("🧩 SCA - Dependency Check", loaded_reports["sca"])
html += html_section("🔒 Secrets Scan - TruffleHog", loaded_reports["trufflehog"])
html += html_section("📦 SBOM - Syft", loaded_reports["sbom"])
html += html_section("🐳 Docker Scan - Trivy", loaded_reports["trivy"])
html += html_section("🌐 DAST - Nikto", loaded_reports["nikto"])

html += """
</body>
</html>
"""

# -----------------------------------------------------
# Sauvegarde du dashboard
# -----------------------------------------------------

output_file = "security-dashboard.html"
with open(output_file, "w", encoding="utf-8") as f:
    f.write(html)

print(f"\n✅ Dashboard généré : {output_file}\n")
