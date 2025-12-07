import json
import os
import html

# ---------- SAFE READING ----------
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


# ---------- SEMGREP ----------
def parse_semgrep():
    data = safe_json("reports/semgrep-report/semgrep.json")
    html_out = "<h2>🔍 SAST - Semgrep</h2>"

    if not data:
        return html_out + "<p><i>Rapport introuvable.</i></p>"

    if data.get("errors"):
        err = data["errors"][0].get("message", "Erreur inconnue")
        return html_out + f"<p style='color:#b71c1c;'><b>Erreur Semgrep :</b> {html.escape(err)}</p>"

    results = data.get("results", [])
    if not results:
        return html_out + "<p>Aucun problème trouvé ✅</p>"

    html_out += """
    <table class="report-table">
      <tr>
        <th>Fichier</th>
        <th>Ligne</th>
        <th>Sévérité</th>
        <th>Description</th>
      </tr>
    """

    for r in results:
        html_out += f"""
        <tr>
            <td>{html.escape(r.get('path','?'))}</td>
            <td>{r.get('start',{}).get('line','?')}</td>
            <td>{r.get('extra',{}).get('severity','N/A')}</td>
            <td>{html.escape(r.get('extra',{}).get('message',''))}</td>
        </tr>
        """

    html_out += "</table>"
    return html_out


# ---------- TRIVY ----------
def parse_trivy():
    data = safe_json("reports/trivy-report/trivy.json")
    html_out = "<h2>🐳 Docker Scan - Trivy</h2>"

    if not data:
        return html_out + "<p><i>Rapport introuvable.</i></p>"

    results = data.get("Results", [])
    vulns = []

    for r in results:
        vulns.extend(r.get("Vulnerabilities", []))

    if not vulns:
        return html_out + "<p>Aucune vulnérabilité détectée ✅</p>"

    html_out += """
    <table class="report-table">
      <tr>
        <th>CVE</th>
        <th>Package</th>
        <th>Version installée</th>
        <th>Version corrigée</th>
        <th>Sévérité</th>
      </tr>
    """

    for v in vulns[:50]:
        html_out += f"""
        <tr>
            <td>{v.get('VulnerabilityID','?')}</td>
            <td>{v.get('PkgName','?')}</td>
            <td>{v.get('InstalledVersion','?')}</td>
            <td>{v.get('FixedVersion','N/A')}</td>
            <td>{v.get('Severity','?')}</td>
        </tr>
        """

    html_out += "</table>"
    return html_out


# ---------- FINAL HTML ----------
page = f"""
<html>
<head>
<meta charset="utf-8">
<title>DevSecOps Security Dashboard</title>

<style>
  body {{
    font-family: Arial, sans-serif;
    background: #f2f4f7;
    margin: 0;
    padding: 20px;
  }}

  h1 {{
    background: #0d47a1;
    color: white;
    padding: 16px;
    border-radius: 6px;
    margin-bottom: 30px;
  }}

  h2 {{
    color: #0d47a1;
    border-left: 6px solid #0d47a1;
    padding-left: 10px;
    margin-top: 25px;
  }}

  .section {{
    background: white;
    padding: 20px;
    border-radius: 8px;
    margin-bottom: 20px;
    box-shadow: 0 2px 6px rgba(0,0,0,0.15);
  }}

  .report-table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 15px;
  }}

  .report-table th, .report-table td {{
    border: 1px solid #ccc;
    padding: 8px;
  }}

  .report-table th {{
    background: #e3f2fd;
  }}
</style>

</head>
<body>

<h1>🔐 DevSecOps – Security Dashboard</h1>

<div class="section">{parse_semgrep()}</div>
<div class="section">{parse_trivy()}</div>

</body>
</html>
"""

with open("security-dashboard.html", "w", encoding="utf-8") as f:
    f.write(page)

print("✅ Dashboard PRO généré avec succès !")
