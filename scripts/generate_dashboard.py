import json, os, html

# =======================
#   HELPERS
# =======================
def safe_read(path):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    return None

def safe_json(path):
    try:
        data = safe_read(path)
        return json.loads(data) if data else None
    except:
        return None


# =======================
#   SEMGREP (SAST)
# =======================
def section_semgrep():
    data = safe_json("reports/semgrep-report/semgrep.json")
    out = "<h2>🔍 SAST - Semgrep</h2>"

    if not data:
        return out + "<p><i>Rapport introuvable.</i></p>"

    # Erreur règle
    if data.get("errors"):
        err = html.escape(data["errors"][0]["message"])
        return out + f"<p style='color:#c62828'><b>Erreur Semgrep :</b> {err}</p>"

    results = data.get("results", [])
    if not results:
        return out + "<p>Aucun problème détecté ✔️</p>"

    out += """
    <table class="report-table">
      <tr><th>Fichier</th><th>Ligne</th><th>Sévérité</th><th>Description</th></tr>
    """

    for r in results:
        out += f"""
        <tr>
          <td>{html.escape(r['path'])}</td>
          <td>{r['start']['line']}</td>
          <td>{r['extra'].get('severity','N/A')}</td>
          <td>{html.escape(r['extra'].get('message',''))}</td>
        </tr>
        """

    out += "</table>"
    return out


# =======================
#   DEPENDENCY-CHECK (SCA)
# =======================
def section_sca():
    path = "reports/dependency-report/dependency-check-report.html"
    out = "<h2>🧩 SCA - Dependency Check</h2>"
    
    if not os.path.exists(path):
        return out + "<p><i>Rapport introuvable.</i></p>"

    # Résumé simple : compter les occurrences HIGH et CRITICAL
    content = safe_read(path)
    high = content.count("HIGH")
    critical = content.count("CRITICAL")

    out += f"""
    <p><b>Résumé :</b></p>
    <ul>
      <li><b>Vulnérabilités HIGH :</b> {high}</li>
      <li><b>Vulnérabilités CRITICAL :</b> {critical}</li>
    </ul>
    <p><i>Voir le rapport complet dans dependency-check-report.html</i></p>
    """
    return out


# =======================
#   TRUFFLEHOG (SECRETS)
# =======================
def section_secrets():
    data = safe_json("reports/trufflehog-report/trufflehog.json")
    out = "<h2>🔒 Secrets Scan - TruffleHog</h2>"

    if not data:
        return out + "<p><i>Rapport introuvable.</i></p>"

    if isinstance(data, dict):
        return out + "<p>Aucun secret détecté ✔️</p>"

    findings = []

    for line in safe_read("reports/trufflehog-report/trufflehog.json").splitlines():
        try:
            findings.append(json.loads(line))
        except:
            pass

    if not findings:
        return out + "<p>Aucun secret détecté ✔️</p>"

    out += "<p><b>Secrets potentiels trouvés :</b></p><ul>"

    for f in findings[:10]:
        out += f"<li>Source : {html.escape(str(f.get('Source','?')))}</li>"

    out += "</ul>"
    return out


# =======================
#   SYFT SBOM
# =======================
def section_sbom():
    data = safe_json("reports/sbom-report/sbom.json")
    out = "<h2>📦 SBOM - Syft</h2>"

    if not data:
        return out + "<p><i>Rapport introuvable.</i></p>"

    artifacts = data.get("artifacts", [])
    out += f"<p><b>Composants détectés :</b> {len(artifacts)}</p>"

    out += """
    <table class="report-table">
      <tr><th>Nom</th><th>Version</th><th>Type</th></tr>
    """

    for a in artifacts[:15]:
        out += f"""
        <tr>
          <td>{html.escape(a.get('name','?'))}</td>
          <td>{html.escape(a.get('version','?'))}</td>
          <td>{html.escape(a.get('type','?'))}</td>
        </tr>
        """

    out += "</table>"
    return out


# =======================
#   TRIVY (DOCKER)
# =======================
def section_trivy():
    data = safe_json("reports/trivy-report/trivy.json")
    out = "<h2>🐳 Docker Scan - Trivy</h2>"

    if not data:
        return out + "<p><i>Rapport introuvable.</i></p>"

    vulns = []
    for r in data.get("Results", []):
        vulns.extend(r.get("Vulnerabilities", []))

    if not vulns:
        return out + "<p>Aucune vulnérabilité détectée ✔️</p>"

    out += """
    <table class="report-table">
      <tr><th>CVE</th><th>Package</th><th>Version</th><th>Fix</th><th>Sévérité</th></tr>
    """

    for v in vulns[:50]:
        out += f"""
        <tr>
          <td>{v['VulnerabilityID']}</td>
          <td>{v.get('PkgName')}</td>
          <td>{v.get('InstalledVersion')}</td>
          <td>{v.get('FixedVersion','N/A')}</td>
          <td>{v['Severity']}</td>
        </tr>
        """

    out += "</table>"
    return out


# =======================
#   NIKTO (DAST)
# =======================
def section_nikto():
    content = safe_read("reports/nikto-report/nikto.txt")
    out = "<h2>🌐 DAST - Nikto</h2>"

    if not content:
        return out + "<p><i>Rapport introuvable.</i></p>"

    snippet = html.escape("\n".join(content.splitlines()[:25]))

    return out + f"<pre>{snippet}</pre>"


# =======================
#   QODANA
# =======================
def section_qodana():
    out = "<h2>🔍 Code Quality - Qodana</h2>"
    out += "<p>Analyse Qodana exécutée. Voir les résultats dans Qodana Cloud.</p>"
    return out


# =======================
#   FINAL HTML
# =======================
html_page = f"""
<html>
<head>
<meta charset="utf-8">
<title>DevSecOps Dashboard</title>

<style>
  body {{
    font-family: Arial, sans-serif;
    background: #f4f6f8;
    padding: 20px;
  }}
  h1 {{
    background: #0d47a1;
    color: white;
    padding: 16px;
    border-radius: 6px;
  }}
  .section {{
    background: white;
    padding: 20px;
    margin-top: 20px;
    border-radius: 8px;
    box-shadow: 0 2px 6px rgba(0,0,0,0.15);
  }}
  .report-table {{
    width: 100%;
    border-collapse: collapse;
  }}
  .report-table th {{
    background: #e3f2fd;
    padding: 8px;
  }}
  .report-table td {{
    border: 1px solid #ddd;
    padding: 8px;
  }}
</style>
</head>
<body>

<h1>🔐 DevSecOps – Security Dashboard</h1>

<div class="section">{section_semgrep()}</div>
<div class="section">{section_sca()}</div>
<div class="section">{section_secrets()}</div>
<div class="section">{section_sbom()}</div>
<div class="section">{section_trivy()}</div>
<div class="section">{section_nikto()}</div>
<div class="section">{section_qodana()}</div>

</body>
</html>
"""

with open("security-dashboard.html", "w", encoding="utf-8") as f:
    f.write(html_page)

print("✅ Dashboard COMPLET généré !")
