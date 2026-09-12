#!/usr/bin/env python3
"""
evaluate.py - confront normalized findings against the A2 ground truth.

Usage:
    python3 evaluate.py <run_dir> --ground-truth ground-truth/crapi-a2.yaml
                        [--out evaluation.json]

Computes, per A2 weakness:
    detected            at least one finding matches the weakness
    matched_artifacts   how many of the expected artifacts were covered
    artifact_recall     matched_artifacts / expected_count
    by_family           which tool families actually detected it
    bound               the pre-registered theoretical upper bound
    within_bound        whether the observed families are a subset of the bound

And overall:
    weakness_recall     detected weaknesses / total weaknesses
    per-family recall against each family's pre-registered bound
    false positives on the verified_absent controls

MATCHING RULE
A finding matches a weakness when its CWE equals the expected CWE AND its
location file is one of the affected artifacts (when the weakness lists them)
or matches the weakness artifact kind (when it does not). Matching is on file
granularity, never on line number: tools disagree on line attribution for
structural weaknesses, and A2 counts affected artifacts, not findings.
"""
import argparse
import json
import re
from collections import defaultdict
from pathlib import Path

import yaml

# Tool to family mapping, aligned with the pre-registered bounds in A2.
FAMILY = {
    "semgrep": "sast",
    "trivy-fs": "sca",
    "gitleaks": "secrets",
    "checkov": "iac",
    "trivy-config": "iac",
    "trivy-image": "image",
    "zap-unauth": "dast",
    "zap-auth": "dast",
    "nuclei": "dast",
}

# Artifact kind to path pattern, used when a weakness lists no explicit files.
KIND_PATTERN = {
    "dockerfile": re.compile(r"^services/[^/]+/Dockerfile$"),
    "k8s_manifest": re.compile(r"^deploy/k8s/base/"),
    "github_workflow": re.compile(r"^\.github/workflows/"),
    "compose": re.compile(r"^deploy/docker/docker-compose[^/]*\.ya?ml$"),
}


def load_findings(run_dir: Path):
    out = []
    with open(run_dir / "findings.jsonl") as fh:
        for line in fh:
            if line.strip():
                out.append(json.loads(line))
    return out


def file_of(finding) -> str:
    loc = finding.get("location") or ""
    return loc.split(":")[0]


def is_excluded(path: str, excluded_globs) -> bool:
    for pat in excluded_globs:
        core = pat.replace("**", "").replace("*", "").strip("/")
        if core and core in path:
            return True
    return False


def matches(finding, weakness) -> bool:
    """A finding matches a weakness when the CWE is identical AND the file it
    points at belongs to the weakness scope.

    Scope is resolved in decreasing order of precision:
      1. an explicit `affected` list of files
      2. a `path_prefix` restricting an artifact kind to a subtree
      3. the artifact-kind pattern alone
    Anything outside that scope is not a detection of THIS weakness, even when
    the CWE matches: the same CWE legitimately arises elsewhere in the corpus.
    """
    if finding.get("cwe_id") != weakness["cwe"]:
        return False
    f = file_of(finding)
    if not f:
        return False
    affected = weakness.get("affected")
    if affected:
        return f in affected
    prefix = weakness.get("path_prefix")
    pattern = KIND_PATTERN.get(weakness.get("artifacts", ""))
    if prefix:
        return f.startswith(prefix) and bool(pattern and pattern.search(f))
    return bool(pattern and pattern.search(f))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir")
    ap.add_argument("--ground-truth", required=True)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    run_dir = Path(args.run_dir)
    gt = yaml.safe_load(open(args.ground_truth))
    findings = load_findings(run_dir)

    excluded = [e["path"] for e in gt.get("scope", {}).get("excluded", [])]
    scoped = [f for f in findings if not is_excluded(file_of(f), excluded)]

    results = []
    for w in gt["weaknesses"]:
        hits = [f for f in scoped if matches(f, w)]
        files_hit = sorted({file_of(f) for f in hits})
        families = sorted({FAMILY.get(f["tool"], f["tool"]) for f in hits})
        tools = sorted({f["tool"] for f in hits})
        bound = [fam for fam in w.get("detectable_by", [])]
        results.append({
            "id": w["id"],
            "weakness": w["weakness"],
            "cwe": w["cwe"],
            "expected_count": w["expected_count"],
            "detected": bool(hits),
            "findings": len(hits),
            "matched_artifacts": len(files_hit),
            "artifact_recall": round(min(len(files_hit), w["expected_count"])
                                     / w["expected_count"], 3)
            if w["expected_count"] else None,
            "over_count": max(0, len(files_hit) - w["expected_count"]),
            "by_family": families,
            "by_tool": tools,
            "bound": bound,
            "within_bound": set(families).issubset(set(bound)),
            "matched_files": files_hit[:10],
        })

    # per-family recall against pre-registered bounds
    bounds = gt.get("theoretical_upper_bound", {})
    family_recall = {}
    for fam, bound_n in bounds.items():
        detected = sum(1 for r in results
                       if fam in r["by_family"])
        family_recall[fam] = {
            "detected": detected,
            "bound": bound_n,
            "recall": round(detected / bound_n, 3) if bound_n else None,
        }

    # false positives on verified-absent controls
    fp = []
    for na in gt.get("verified_absent", []):
        cwe = na.get("expected_cwe_if_present")
        if not cwe:
            continue
        prefix = na.get("scope_prefix")
        offenders = [f for f in scoped
                     if f.get("cwe_id") == cwe
                     and (not prefix or file_of(f).startswith(prefix))]
        fp.append({
            "id": na["id"],
            "control": na["control"],
            "cwe": cwe,
            "scope_prefix": prefix,
            "findings_on_absent_control": len(offenders),
            "by_tool": dict(sorted(
                {t: sum(1 for f in offenders if f["tool"] == t)
                 for t in {f["tool"] for f in offenders}}.items())),
        })

    detected_n = sum(1 for r in results if r["detected"])
    report = {
        "run": run_dir.name,
        "ground_truth": gt["target"] + " A2",
        "commit": gt["commit"],
        "findings_total": len(findings),
        "findings_in_scope": len(scoped),
        "findings_excluded": len(findings) - len(scoped),
        "weaknesses_total": len(results),
        "weaknesses_detected": detected_n,
        "weakness_recall": round(detected_n / len(results), 3),
        "family_recall": family_recall,
        "per_weakness": results,
        "verified_absent_checks": fp,
    }

    out = Path(args.out) if args.out else run_dir / "evaluation-a2.json"
    out.write_text(json.dumps(report, indent=2))

    print(f"A2 recall: {detected_n}/{len(results)} weaknesses detected "
          f"({report['weakness_recall']:.0%})")
    print(f"in scope: {len(scoped)} findings "
          f"({report['findings_excluded']} excluded as third-party)\n")
    for r in results:
        flag = "OK " if r["detected"] else "MISS"
        extra = "" if r["within_bound"] else "  [!] outside pre-registered bound"
        if r["over_count"]:
            extra += f"  [!] {r['over_count']} files beyond expected scope"
        print(f"  {flag} {r['id']}  {r['cwe']:<9} "
              f"{r['matched_artifacts']}/{r['expected_count']} artifacts, "
              f"{r['findings']:>4} findings  {','.join(r['by_tool']) or '-'}{extra}")
    print()
    for f in fp:
        print(f"  {f['id']}: {f['findings_on_absent_control']} findings on a "
              f"verified-absent control ({f['cwe']}) {f['by_tool'] or ''}")
    print(f"\nwritten: {out}")


if __name__ == "__main__":
    main()
