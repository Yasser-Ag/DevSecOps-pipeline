#!/usr/bin/env python3
"""
normalize.py — Stage 7 : normalisation CWE + déduplication inter-outils.

Usage :  python3 normalize.py <run_dir> [--lab /opt/devsecops-lab]
Lit     : 01-sast-semgrep.json, 02-sca-trivy.json, 03-secrets-gitleaks.json
Écrit   : findings.jsonl  (un finding normalisé par ligne)
          findings-dedup.jsonl
          summary.json    (compteurs bruts / dédupliqués / par outil / par CWE)

Schéma unifié d'un finding :
  tool, stage, layer, target, cwe_id, cwe_ids, severity, location, rule,
  title, evidence, raw_ref, detected_by
"""
import hashlib, json, re, sys, os
from collections import Counter, defaultdict
from pathlib import Path

# ------------------------------------------------------------------ config
SEVERITY = {                     # échelle unique à 4 niveaux
    # semgrep
    "ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW",
    # trivy
    "CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW", "UNKNOWN": "LOW",
}

# gitleaks n'émet pas de CWE : table de correspondance par RuleID
GITLEAKS_CWE = {
    "private-key":           ("CWE-321", "HIGH"),      # hard-coded cryptographic key
    "generic-api-key":       ("CWE-798", "HIGH"),      # hard-coded credentials
    "jwt":                   ("CWE-798", "HIGH"),
    "aws-access-token":      ("CWE-798", "CRITICAL"),
    "gcp-api-key":           ("CWE-798", "CRITICAL"),
    "github-pat":            ("CWE-798", "CRITICAL"),
    "slack-webhook-url":     ("CWE-798", "MEDIUM"),
    "hashicorp-tf-password": ("CWE-798", "HIGH"),
}
GITLEAKS_DEFAULT = ("CWE-798", "MEDIUM")

CWE_RE = re.compile(r"CWE-\d+")

def redact(secret: str) -> str:
    """Ne jamais copier un secret dans le dataset publié."""
    h = hashlib.sha256(secret.encode()).hexdigest()[:12]
    return f"{secret[:8]}…[sha256:{h}]"

def rel(path: str, lab: str) -> str:
    return os.path.relpath(path, lab) if path.startswith(lab) else path

# ------------------------------------------------------------------ adapters
def from_semgrep(doc, lab, target):
    for r in doc.get("results", []):
        meta = r.get("extra", {}).get("metadata", {})
        cwes = []
        for c in meta.get("cwe", []) or []:
            m = CWE_RE.search(c)
            if m: cwes.append(m.group())
        loc = f'{rel(r["path"], lab)}:{r["start"]["line"]}'
        yield {
            "tool": "semgrep", "stage": "sast", "layer": "code", "target": target,
            "cwe_id": cwes[0] if cwes else None, "cwe_ids": cwes,
            "severity": SEVERITY.get(r["extra"].get("severity", "INFO"), "LOW"),
            "location": loc, "rule": r["check_id"],
            "title": r["extra"].get("message", "")[:160],
            "evidence": None, "raw_ref": f'semgrep:{r["check_id"]}@{loc}',
        }

def from_trivy(doc, lab, target):
    for res in doc.get("Results", []) or []:
        tfile = res.get("Target", "")
        for v in res.get("Vulnerabilities", []) or []:
            cwes = v.get("CweIDs", []) or []
            loc = f'{tfile}:{v.get("PkgName")}@{v.get("InstalledVersion")}'
            yield {
                "tool": "trivy", "stage": "sca", "layer": "dependency", "target": target,
                "cwe_id": cwes[0] if cwes else None, "cwe_ids": cwes,
                "severity": SEVERITY.get(v.get("Severity", "UNKNOWN"), "LOW"),
                "location": loc, "rule": v.get("VulnerabilityID"),
                "title": (v.get("Title") or v.get("VulnerabilityID"))[:160],
                "evidence": v.get("PkgIdentifier", {}).get("PURL"),
                "raw_ref": f'trivy:{v.get("VulnerabilityID")}@{loc}',
            }

def from_gitleaks(doc, lab, target):
    for f in doc or []:
        cwe, sev = GITLEAKS_CWE.get(f.get("RuleID"), GITLEAKS_DEFAULT)
        loc = f'{rel(f["File"], lab)}:{f["StartLine"]}'
        yield {
            "tool": "gitleaks", "stage": "secrets", "layer": "repo", "target": target,
            "cwe_id": cwe, "cwe_ids": [cwe], "severity": sev,
            "location": loc, "rule": f.get("RuleID"),
            "title": f.get("Description", "")[:160],
            "evidence": redact(f.get("Secret", "")),      # <-- jamais le secret en clair
            "raw_ref": f'gitleaks:{f.get("RuleID")}@{loc}',
        }

ADAPTERS = {
    "01-sast-semgrep.json":    from_semgrep,
    "02-sca-trivy.json":       from_trivy,
    "03-secrets-gitleaks.json": from_gitleaks,
}

# ------------------------------------------------------------------ main
def main(run_dir: Path, lab: str):
    meta = dict(l.split("=", 1) for l in (run_dir / "meta.txt").read_text().splitlines() if "=" in l)
    target = meta.get("target", "unknown")

    findings = []
    for fname, adapter in ADAPTERS.items():
        p = run_dir / fname
        if not p.exists():
            continue
        try:
            doc = json.loads(p.read_text() or "null")
        except json.JSONDecodeError:
            doc = None
        findings.extend(adapter(doc, lab, target))

    # --- déduplication : même CWE + même location + même règle => un seul finding
    #     (la règle fait partie de la clé : deux CVE distinctes sur le même paquet
    #      partagent souvent le même CWE et ne doivent PAS être fusionnées)
    dedup = {}
    for f in findings:
        key = (f["cwe_id"], f["location"], f["rule"])
        if key in dedup:
            dedup[key]["detected_by"].append(f["tool"])
            dedup[key]["detected_by"] = sorted(set(dedup[key]["detected_by"]))
        else:
            dedup[key] = {**f, "detected_by": [f["tool"]]}

    # --- écriture
    with open(run_dir / "findings.jsonl", "w") as fh:
        for f in findings: fh.write(json.dumps(f) + "\n")
    with open(run_dir / "findings-dedup.jsonl", "w") as fh:
        for f in dedup.values(): fh.write(json.dumps(f) + "\n")

    summary = {
        "target": target,
        "raw_total": len(findings),
        "dedup_total": len(dedup),
        "raw_by_tool": dict(Counter(f["tool"] for f in findings)),
        "dedup_by_tool": dict(Counter(t for f in dedup.values() for t in f["detected_by"])),
        "by_severity": dict(Counter(f["severity"] for f in dedup.values())),
        "by_cwe": dict(Counter(f["cwe_id"] or "NO-CWE" for f in dedup.values()).most_common()),
        "no_cwe": sum(1 for f in dedup.values() if not f["cwe_id"]),
        "no_cwe_by_tool": dict(Counter(f["tool"] for f in dedup.values() if not f["cwe_id"])),
        "multi_tool": sum(1 for f in dedup.values() if len(f["detected_by"]) > 1),
    }
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2))

    print(f"{target}: {len(findings)} bruts -> {len(dedup)} dédupliqués "
          f"({summary['no_cwe']} sans CWE, {summary['multi_tool']} multi-outils)")
    print(json.dumps(summary["by_severity"]))

if __name__ == "__main__":
    lab = "/opt/devsecops-lab"
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if "--lab" in sys.argv:
        lab = sys.argv[sys.argv.index("--lab") + 1]
    if not args:
        sys.exit("usage: normalize.py <run_dir> [--lab PATH]")
    main(Path(args[0]), lab)
