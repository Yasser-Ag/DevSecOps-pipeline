#!/usr/bin/env python3
"""
normalize.py - CWE normalization and cross-tool deduplication.

Usage:  python3 normalize.py <run_dir> [--lab /opt/devsecops-lab]

Reads (whichever are present):
    01-sast-semgrep.json                  Semgrep           - code
    02-sca-trivy.json                     Trivy fs          - dependencies
    03-secrets-gitleaks.json              gitleaks          - secrets
    04a-iac-checkov.json/results_json.json  checkov         - IaC / config
    04b-config-trivy.json                 Trivy config      - IaC / config
    05-image-*.json                       Trivy image       - container images

Writes:
    findings.jsonl         one normalized finding per line (raw population)
    findings-dedup.jsonl   after cross-tool deduplication
    summary.json           counters used by the pipeline summary

Unified finding schema:
    tool, stage, layer, target, cwe_id, cwe_ids, severity, location, rule,
    title, evidence, raw_ref, detected_by

Deduplication key: (cwe_id, location, rule).
The rule is part of the key on purpose: two distinct CVEs affecting the same
package frequently share a CWE and must NOT be merged.
"""
import hashlib
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

# --------------------------------------------------------------------- config
SEVERITY = {
    # semgrep
    "ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW",
    # trivy (all scanners)
    "CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
    "LOW": "LOW", "UNKNOWN": "LOW",
}

# gitleaks emits no CWE: rule-to-CWE mapping.
GITLEAKS_CWE = {
    "private-key":           ("CWE-321", "HIGH"),
    "generic-api-key":       ("CWE-798", "HIGH"),
    "jwt":                   ("CWE-798", "HIGH"),
    "aws-access-token":      ("CWE-798", "CRITICAL"),
    "gcp-api-key":           ("CWE-798", "CRITICAL"),
    "github-pat":            ("CWE-798", "CRITICAL"),
    "slack-webhook-url":     ("CWE-798", "MEDIUM"),
    "hashicorp-tf-password": ("CWE-798", "HIGH"),
}
GITLEAKS_DEFAULT = ("CWE-798", "MEDIUM")

# Trivy misconfiguration IDs carry no CWE: prefix-based mapping.
# Rationale: Trivy groups checks by provider prefix (DS = Dockerfile,
# KSV = Kubernetes Security, AVD-* = cloud providers). The mapping is coarse
# by design and is reported as a limitation rather than presented as exact.
TRIVY_MISCONF_CWE = {
    "DS002":  "CWE-250",   # root user in container
    "DS004":  "CWE-250",
    "DS005":  "CWE-1357",  # COPY/ADD from unpinned source
    "DS013":  "CWE-1357",  # unpinned base image tag
    "DS026":  "CWE-1357",
    "KSV001": "CWE-250",   # can elevate privileges
    "KSV003": "CWE-250",
    "KSV005": "CWE-250",
    "KSV011": "CWE-770",   # no CPU limit
    "KSV012": "CWE-250",   # runs as root
    "KSV013": "CWE-1357",  # image tag not pinned
    "KSV014": "CWE-732",   # writable root filesystem
    "KSV015": "CWE-770",   # no CPU request
    "KSV016": "CWE-770",   # no memory request
    "KSV018": "CWE-770",   # no memory limit
    "KSV020": "CWE-250",   # runs with low UID
    "KSV021": "CWE-250",
    "KSV023": "CWE-732",   # hostPath volume
    "KSV029": "CWE-732",
    "KSV030": "CWE-732",   # seccomp profile not set
    "KSV037": "CWE-668",   # default namespace
    "KSV106": "CWE-250",
}
# Fallback per prefix when the exact ID is unknown.
TRIVY_MISCONF_PREFIX = {
    "DS":  "CWE-1357",
    "KSV": "CWE-250",
    "AVD": "CWE-284",
}
TRIVY_MISCONF_DEFAULT = "CWE-284"

# checkov open source does not populate `severity` (commercial edition only).
# All checkov findings are therefore assigned MEDIUM and this is declared as a
# limitation; no severity is invented per rule.
CHECKOV_SEVERITY_DEFAULT = "MEDIUM"

# checkov check_id to CWE, by framework prefix and by common check families.
CHECKOV_CWE = {
    "CKV_K8S_20": "CWE-250",   # allowPrivilegeEscalation
    "CKV_K8S_21": "CWE-668",   # default namespace
    "CKV_K8S_22": "CWE-732",   # read-only root filesystem
    "CKV_K8S_23": "CWE-250",   # run as non-root
    "CKV_K8S_28": "CWE-250",   # minimise capabilities
    "CKV_K8S_29": "CWE-1357",
    "CKV_K8S_30": "CWE-250",
    "CKV_K8S_31": "CWE-732",   # seccomp
    "CKV_K8S_37": "CWE-250",   # capabilities
    "CKV_K8S_38": "CWE-522",   # service account token
    "CKV_K8S_40": "CWE-250",   # high UID
    "CKV_K8S_43": "CWE-1357",  # image digest not pinned
    "CKV_DOCKER_2": "CWE-1008",  # no HEALTHCHECK
    "CKV_DOCKER_3": "CWE-250",   # no USER
    "CKV_DOCKER_7": "CWE-1357",  # unpinned base image
    "CKV_GHA_1":  "CWE-94",      # workflow command injection
    "CKV_GHA_2":  "CWE-269",     # excessive permissions
    "CKV_GHA_3":  "CWE-829",     # unpinned action
}
CHECKOV_PREFIX_CWE = {
    "CKV_K8S":    "CWE-284",
    "CKV_DOCKER": "CWE-250",
    "CKV_GHA":    "CWE-829",
    "CKV_SECRET": "CWE-798",
    "CKV_AWS":    "CWE-284",
    "CKV_AZURE":  "CWE-284",
    "CKV_GCP":    "CWE-284",
}
CHECKOV_DEFAULT = "CWE-284"

# ZAP risk codes: 0=Informational, 1=Low, 2=Medium, 3=High.
# ZAP defines no Critical level; High is its ceiling.
ZAP_RISK = {"0": "LOW", "1": "LOW", "2": "MEDIUM", "3": "HIGH"}

CWE_RE = re.compile(r"CWE-\d+")


def redact(secret: str) -> str:
    """Never copy a secret into the published dataset."""
    h = hashlib.sha256(secret.encode()).hexdigest()[:12]
    return f"{secret[:8]}...[sha256:{h}]"


def rel(path, lab: str, target: str = "") -> str:
    """Normalize any path to a target-relative form.

    Tools report locations inconsistently: checkov emits absolute paths,
    Trivy config emits paths already relative to the scanned directory.
    Without this normalization, locations are not comparable across tools and
    cross-tool agreement is measured as artificially zero.
    """
    if not path:
        return ""
    p = str(path).lstrip("/")
    lab_stripped = lab.lstrip("/")
    if p.startswith(lab_stripped):
        p = os.path.relpath(p, lab_stripped)
    if target and p.startswith(target + "/"):
        p = p[len(target) + 1:]
    return p


def load(path: Path):
    try:
        return json.loads(path.read_text() or "null")
    except (json.JSONDecodeError, OSError):
        return None


# ------------------------------------------------------------------- adapters
def from_semgrep(doc, lab, target):
    for r in (doc or {}).get("results", []):
        meta = r.get("extra", {}).get("metadata", {})
        cwes = [m.group() for c in (meta.get("cwe") or [])
                if (m := CWE_RE.search(str(c)))]
        loc = f'{rel(r["path"], lab, target)}:{r["start"]["line"]}'
        yield {
            "tool": "semgrep", "stage": "sast", "layer": "code", "target": target,
            "cwe_id": cwes[0] if cwes else None, "cwe_ids": cwes,
            "severity": SEVERITY.get(r["extra"].get("severity", "INFO"), "LOW"),
            "location": loc, "rule": r["check_id"],
            "title": (r["extra"].get("message") or "")[:160],
            "evidence": None, "raw_ref": f'semgrep:{r["check_id"]}@{loc}',
        }


def from_trivy_fs(doc, lab, target):
    for res in (doc or {}).get("Results") or []:
        tfile = rel(res.get("Target", ""), lab, target)
        for v in res.get("Vulnerabilities") or []:
            cwes = v.get("CweIDs") or []
            loc = f'{tfile}:{v.get("PkgName")}@{v.get("InstalledVersion")}'
            yield {
                "tool": "trivy-fs", "stage": "sca", "layer": "dependency",
                "target": target,
                "cwe_id": cwes[0] if cwes else None, "cwe_ids": cwes,
                "severity": SEVERITY.get(v.get("Severity", "UNKNOWN"), "LOW"),
                "location": loc, "rule": v.get("VulnerabilityID"),
                "title": (v.get("Title") or v.get("VulnerabilityID") or "")[:160],
                "evidence": (v.get("PkgIdentifier") or {}).get("PURL"),
                "raw_ref": f'trivy-fs:{v.get("VulnerabilityID")}@{loc}',
            }


def from_gitleaks(doc, lab, target):
    for f in doc or []:
        cwe, sev = GITLEAKS_CWE.get(f.get("RuleID"), GITLEAKS_DEFAULT)
        loc = f'{rel(f.get("File"), lab, target)}:{f.get("StartLine")}'
        yield {
            "tool": "gitleaks", "stage": "secrets", "layer": "repo",
            "target": target,
            "cwe_id": cwe, "cwe_ids": [cwe], "severity": sev,
            "location": loc, "rule": f.get("RuleID"),
            "title": (f.get("Description") or "")[:160],
            "evidence": redact(f.get("Secret", "")),
            "raw_ref": f'gitleaks:{f.get("RuleID")}@{loc}',
        }


def _checkov_cwe(check_id: str) -> str:
    if check_id in CHECKOV_CWE:
        return CHECKOV_CWE[check_id]
    for prefix, cwe in CHECKOV_PREFIX_CWE.items():
        if check_id.startswith(prefix):
            return cwe
    return CHECKOV_DEFAULT


def from_checkov(doc, lab, target):
    # checkov returns a list of report objects, one per framework.
    reports = doc if isinstance(doc, list) else [doc] if doc else []
    for report in reports:
        if not isinstance(report, dict):
            continue
        framework = report.get("check_type", "unknown")
        for c in (report.get("results") or {}).get("failed_checks") or []:
            cwe = _checkov_cwe(c.get("check_id", ""))
            line = (c.get("file_line_range") or [None])[0]
            loc = f'{rel(c.get("file_abs_path") or c.get("file_path"), lab, target)}:{line}'
            yield {
                "tool": "checkov", "stage": "iac",
                "layer": framework, "target": target,
                "cwe_id": cwe, "cwe_ids": [cwe],
                "severity": CHECKOV_SEVERITY_DEFAULT,
                "location": loc, "rule": c.get("check_id"),
                "title": (c.get("check_name") or "")[:160],
                "evidence": c.get("resource"),
                "raw_ref": f'checkov:{c.get("check_id")}@{loc}',
            }


def _trivy_misconf_cwe(mid: str) -> str:
    if mid in TRIVY_MISCONF_CWE:
        return TRIVY_MISCONF_CWE[mid]
    for prefix, cwe in TRIVY_MISCONF_PREFIX.items():
        if mid.startswith(prefix):
            return cwe
    return TRIVY_MISCONF_DEFAULT


def from_trivy_config(doc, lab, target):
    for res in (doc or {}).get("Results") or []:
        tfile = rel(res.get("Target", ""), lab, target)
        ctype = res.get("Type", "config")
        for m in res.get("Misconfigurations") or []:
            mid = m.get("ID", "")
            line = ((m.get("CauseMetadata") or {}).get("StartLine")) or None
            loc = f'{tfile}:{line}' if line else tfile
            cwe = _trivy_misconf_cwe(mid)
            yield {
                "tool": "trivy-config", "stage": "iac",
                "layer": ctype, "target": target,
                "cwe_id": cwe, "cwe_ids": [cwe],
                "severity": SEVERITY.get(m.get("Severity", "UNKNOWN"), "LOW"),
                "location": loc, "rule": mid,
                "title": (m.get("Title") or "")[:160],
                "evidence": (m.get("Message") or "")[:200],
                "raw_ref": f'trivy-config:{mid}@{loc}',
            }


def from_trivy_image(doc, lab, target, image):
    for res in (doc or {}).get("Results") or []:
        tfile = res.get("Target", "")
        for v in res.get("Vulnerabilities") or []:
            cwes = v.get("CweIDs") or []
            loc = f'{image}:{v.get("PkgName")}@{v.get("InstalledVersion")}'
            yield {
                "tool": "trivy-image", "stage": "image", "layer": "container",
                "target": target,
                "cwe_id": cwes[0] if cwes else None, "cwe_ids": cwes,
                "severity": SEVERITY.get(v.get("Severity", "UNKNOWN"), "LOW"),
                "location": loc, "rule": v.get("VulnerabilityID"),
                "title": (v.get("Title") or v.get("VulnerabilityID") or "")[:160],
                "evidence": tfile,
                "raw_ref": f'trivy-image:{v.get("VulnerabilityID")}@{loc}',
            }


def from_zap(doc, lab, target, mode):
    """ZAP groups occurrences under a single alert object; one finding is
    emitted per INSTANCE so that DAST counts remain commensurable with the
    other stages, where one finding is one occurrence."""
    for site in (doc or {}).get("site") or []:
        for a in site.get("alerts") or []:
            raw_cwe = str(a.get("cweid", "")).strip()
            cwe = f"CWE-{raw_cwe}" if raw_cwe and raw_cwe != "-1" else None
            sev = ZAP_RISK.get(str(a.get("riskcode", "0")), "LOW")
            for inst in a.get("instances") or [{}]:
                uri = inst.get("uri", "")
                loc = uri.split("://", 1)[-1].split("?", 1)[0]
                yield {
                    "tool": f"zap-{mode}", "stage": "dast", "layer": "runtime",
                    "target": target,
                    "cwe_id": cwe, "cwe_ids": [cwe] if cwe else [],
                    "severity": sev,
                    "location": loc, "rule": a.get("pluginid"),
                    "title": (a.get("alert") or "")[:160],
                    "evidence": (inst.get("method", "") + " " +
                                 (inst.get("evidence") or "")).strip()[:200],
                    "raw_ref": f'zap-{mode}:{a.get("pluginid")}@{loc}',
                }


def from_nuclei(lines, lab, target):
    for line in lines or []:
        line = line.strip()
        if not line:
            continue
        try:
            n = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = n.get("info") or {}
        classification = info.get("classification") or {}
        cwes = [str(c).upper() for c in (classification.get("cwe-id") or [])]
        loc = str(n.get("matched-at") or n.get("host") or "")
        loc = loc.split("://", 1)[-1].split("?", 1)[0]
        extracted = n.get("extracted-results") or []
        yield {
            "tool": "nuclei", "stage": "dast", "layer": "runtime",
            "target": target,
            "cwe_id": cwes[0] if cwes else None, "cwe_ids": cwes,
            "severity": SEVERITY.get(
                str(info.get("severity", "low")).upper(), "LOW"),
            "location": loc, "rule": n.get("template-id"),
            "title": (info.get("name") or "")[:160],
            "evidence": str(extracted[0])[:200] if extracted else None,
            "raw_ref": f'nuclei:{n.get("template-id")}@{loc}',
        }


# ----------------------------------------------------------------------- main
def collect(run_dir: Path, lab: str, target: str):
    findings = []

    simple = [
        ("01-sast-semgrep.json", from_semgrep),
        ("02-sca-trivy.json", from_trivy_fs),
        ("03-secrets-gitleaks.json", from_gitleaks),
        ("04b-config-trivy.json", from_trivy_config),
    ]
    for fname, adapter in simple:
        p = run_dir / fname
        if p.exists():
            findings.extend(adapter(load(p), lab, target))

    # checkov writes into a directory when --output-file-path is used
    for candidate in (run_dir / "04a-iac-checkov.json",
                      run_dir / "04a-iac-checkov.json" / "results_json.json"):
        if candidate.is_file():
            findings.extend(from_checkov(load(candidate), lab, target))
            break

    # DAST: ZAP (unauthenticated and authenticated passes) and Nuclei
    for fname, mode in (("06a-dast-zap-unauth.json", "unauth"),
                        ("06b-dast-zap-auth.json", "auth")):
        p = run_dir / fname
        if p.is_file():
            findings.extend(from_zap(load(p), lab, target, mode))
    p = run_dir / "06c-dast-nuclei.jsonl"
    if p.is_file():
        findings.extend(from_nuclei(p.read_text().splitlines(), lab, target))

    # one file per scanned image
    for p in sorted(run_dir.glob("05-image-*.json")):
        if p.name == "05-images.txt":
            continue
        image = p.stem.replace("05-image-", "").replace("_", "/", 1)
        findings.extend(from_trivy_image(load(p), lab, target, image))

    return findings


def main(run_dir: Path, lab: str):
    meta_path = run_dir / "meta.txt"
    meta = {}
    if meta_path.exists():
        meta = dict(l.split("=", 1) for l in meta_path.read_text().splitlines()
                    if "=" in l)
    target = meta.get("target", "unknown")

    findings = collect(run_dir, lab, target)

    dedup = {}
    for f in findings:
        key = (f["cwe_id"], f["location"], f["rule"])
        if key in dedup:
            dedup[key]["detected_by"] = sorted(
                set(dedup[key]["detected_by"] + [f["tool"]]))
        else:
            dedup[key] = {**f, "detected_by": [f["tool"]]}

    with open(run_dir / "findings.jsonl", "w") as fh:
        for f in findings:
            fh.write(json.dumps(f) + "\n")
    with open(run_dir / "findings-dedup.jsonl", "w") as fh:
        for f in dedup.values():
            fh.write(json.dumps(f) + "\n")

    # Cross-tool agreement is measured at two granularities, because tools do
    # not all report a line number (Trivy config often reports the file only):
    #   strict : same CWE, same file AND same line
    #   loose  : same CWE, same file
    # Both are reported; the strict figure is the conservative one.
    strict_index, loose_index = {}, {}
    for f in findings:
        if not (f["cwe_id"] and f["location"]):
            continue
        strict_index.setdefault((f["cwe_id"], f["location"]), set()).add(f["tool"])
        file_only = f["location"].split(":")[0]
        loose_index.setdefault((f["cwe_id"], file_only), set()).add(f["tool"])
    consensus = {k: sorted(v) for k, v in strict_index.items() if len(v) > 1}
    consensus_loose = {k: sorted(v) for k, v in loose_index.items() if len(v) > 1}

    summary = {
        "target": target,
        "raw_total": len(findings),
        "dedup_total": len(dedup),
        "raw_by_tool": dict(Counter(f["tool"] for f in findings)),
        "raw_by_stage": dict(Counter(f["stage"] for f in findings)),
        "dedup_by_tool": dict(Counter(t for f in dedup.values()
                                      for t in f["detected_by"])),
        "by_severity": dict(Counter(f["severity"] for f in dedup.values())),
        "by_cwe": dict(Counter(f["cwe_id"] or "NO-CWE"
                               for f in dedup.values()).most_common()),
        "no_cwe": sum(1 for f in dedup.values() if not f["cwe_id"]),
        "no_cwe_by_tool": dict(Counter(f["tool"] for f in dedup.values()
                                       if not f["cwe_id"])),
        "multi_tool": sum(1 for f in dedup.values() if len(f["detected_by"]) > 1),
        "consensus_pairs_strict": len(consensus),
        "consensus_pairs_loose": len(consensus_loose),
        "consensus_by_tools_strict": dict(Counter(
            " + ".join(v) for v in consensus.values()).most_common()),
        "consensus_by_tools_loose": dict(Counter(
            " + ".join(v) for v in consensus_loose.values()).most_common()),
        "files_by_tool": {
            t: len({f["location"].split(":")[0] for f in findings
                    if f["tool"] == t and f["location"]})
            for t in {f["tool"] for f in findings}
        },
    }
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    (run_dir / "consensus.json").write_text(json.dumps({
        "strict": [{"cwe": k[0], "location": k[1], "tools": v}
                   for k, v in consensus.items()],
        "loose": [{"cwe": k[0], "file": k[1], "tools": v}
                  for k, v in consensus_loose.items()],
    }, indent=2))

    print(f"{target}: {len(findings)} raw -> {len(dedup)} dedup "
          f"({summary['no_cwe']} without CWE, "
          f"{summary['consensus_pairs_strict']} strict / "
          f"{summary['consensus_pairs_loose']} loose cross-tool agreements)")
    print(json.dumps(summary["raw_by_stage"]))


if __name__ == "__main__":
    lab = "/opt/devsecops-lab"
    argv = sys.argv[1:]
    if "--lab" in argv:
        i = argv.index("--lab")
        lab = argv[i + 1]
        argv = argv[:i] + argv[i + 2:]
    if not argv:
        sys.exit("usage: normalize.py <run_dir> [--lab PATH]")
    main(Path(argv[0]), lab)
