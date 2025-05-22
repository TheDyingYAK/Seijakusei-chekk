import requests

def get_cvss_rating(score):
    """Return qualitative rating based on CVSS score."""
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score > 0:
        return "Low"
    else:
        return "None"

def format_cvss(score_str):
    """Format CVSS score and label."""
    try:
        score = float(score_str)
        rating = get_cvss_rating(score)
        return f"{score:.1f} ({rating})"
    except Exception:
        return f"{score_str} (Unknown)"

def get_severity_info(vuln):
    """
    Extract CVSS score and convert to rating.
    Looks in multiple possible fields.
    """
    # Try official 'severity' field first
    for item in vuln.get("severity", []):
        if item.get("type") == "CVSS_V3":
            score = item.get("score")
            if score:
                return format_cvss(score)

    # Fallback: check 'database_specific'
    db_specific = vuln.get("database_specific", {})
    cvss = db_specific.get("cvss")
    if isinstance(cvss, dict):
        score = cvss.get("score")
        if score:
            return format_cvss(score)

    return "(not provided)"

def check_osv(package_name, version):
    payload = {
        "version": version,
        "package": {
            "name": package_name,
            "ecosystem": "Debian"
        }
    }

    try:
        response = requests.post("https://api.osv.dev/v1/query", json=payload)
        response.raise_for_status()
        data = response.json()
        vulns = data.get("vulns", [])

        if vulns:
            print(f"\n📦 {package_name} {version} — {len(vulns)} vulnerabilit{'ies' if len(vulns) != 1 else 'y'} found:\n")
            for vuln in vulns:
                vuln_id = vuln.get("id", "UNKNOWN")
                summary = vuln.get("summary", "(no summary available)")
                severity = get_severity_info(vuln)

                print(f"🔸 ID       : {vuln_id}")
                print(f"🔸 Summary  : {summary}")
                print(f"🔸 Severity : {severity}")
                print(f"🔸 More Info: https://osv.dev/vulnerability/{vuln_id}\n")
        else:
            print(f"\n✅ {package_name} {version} — No known vulnerabilities.\n")

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to query {package_name} {version}: {e}\n")

def process_packages_file(filepath):
    print(f"🔍 Scanning packages from {filepath}...\n")
    with open(filepath, 'r') as f:
        for line in f:
            if not line.strip():
                continue
            try:
                pkg, ver = line.strip().split(None, 1)
                check_osv(pkg, ver)
            except ValueError:
                print(f"[WARNING] Skipping malformed line: {line.strip()}\n")

if __name__ == "__main__":
    process_packages_file("packages.txt")

