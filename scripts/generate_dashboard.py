import json
import os

def read_file(path):
    if not os.path.exists(path):
        return "Rapport non trouvé."
    with open(path, "r", errors="ignore") as f:
        return f.read()

html = f"""
<html>
<head>
<title>DevSecOps Security Dashboard</title>
<style>
body {{ font-family: Arial; background: #f4f4f4; padding: 20px; }}
h1 {{ color: #2c3e50; }}
section {{ background: white; padding: 15px; margin-bottom: 20px; border-radius: 8px; }}
pre {{ background: #eee; padding: 10px; border-radius: 5px; }}
</style>
</head>
<body>

<h1>🔐 DevSecOps – Security Dashboard</h1>

<section>
<h2>🔍 SAST - Semgrep</h2>
<pre>{read_file("semgrep.json")}</pre>
</section>

<section>
<h2>🧩 SCA - Dependency Check</h2>
<pre>{read_file("dep-report/dependency-check-report.html")}</pre>
</section>

<section>
<h2>🔒 Secrets Scan - TruffleHog</h2>
<pre>{read_file("trufflehog.json")}</pre>
</section>

<section>
<h2>📦 SBOM - Syft</h2>
<pre>{read_file("sbom.json")}</pre>
</section>

<section>
<h2>🐳 Docker Scan - Trivy</h2>
<pre>{read_file("trivy.json")}</pre>
</section>

<section>
<h2>🌐 DAST - Nikto</h2>
<pre>{read_file("nikto.txt")}</pre>
</section>

<section>
<h2>🔍 Qodana</h2>
<p>Consulte le rapport Qodana dans l’onglet Artifacts.</p>
</section>

</body>
</html>
"""

with open("security-dashboard.html", "w") as f:
    f.write(html)

print("Dashboard généré : security-dashboard.html")
