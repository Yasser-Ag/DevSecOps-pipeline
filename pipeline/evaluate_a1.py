#!/usr/bin/env python3
"""
evaluate_a1.py - confront normalized findings against the A1 ground truth
(crAPI's 18 documented application-level challenges).

Usage:
    python3 evaluate_a1.py <run_dir> --ground-truth ground-truth/crapi-a1.yaml
                           [--out evaluation-a1.json]

WHY TWO MATCHING LEVELS
Dynamic scanners reliably reach a vulnerability while mislabelling its CWE.
Observed on this target: crAPI's documented SSRF endpoint
(/workshop/api/merchant/contact_mechanic, expected CWE-918) is reported by ZAP
as CWE-98; the documented NoSQL injection (/community/api/v2/coupon/
validate-coupon, expected CWE-943) is reported as CWE-134. Matching on CWE
alone would score both as misses although the scanner flagged the right
endpoint. We therefore report:

    strict   CWE equal to the expected CWE, anywhere in the finding set
    endpoint a finding whose location matches the challenge's documented
             endpoint, regardless of the CWE the tool assigned
    either   union of the two — the figure that answers "did any tool reach
             this vulnerability at all?"

Only 4 of 18 challenges document an endpoint (A1 GAP-1), so endpoint matching
is available for those 4 only. This asymmetry is reported, not hidden.

RECALL IS ALSO REPORTED PER TOOL FAMILY, against the pre-registered
theoretical upper bounds recorded in the A1 file. Those bounds were fixed
before any execution and are never revised.
"""
import argparse
import json
from collections import Counter
from pathlib import Path

import yaml

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


def load_findings(run_dir: Path):
    path = run_dir / "findings.jsonl"
    if not path.exists():
        raise SystemExit(f"missing {path}")
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def path_of(location: str) -> str:
    """Reduce a DAST location to its URL path, so it can be compared with the
    endpoint templates documented in A1."""
    if not location:
        return ""
    loc = location.split("://", 1)[-1]
    loc = loc.split("?", 1)[0]
    if "/" in loc:
        first, rest = loc.split("/", 1)
        if ":" in first or first.replace(".", "").isdigit() or "localhost" in first:
            return "/" + rest
    return loc if loc.startswith("/") else "/" + loc


def endpoint_matches(finding_path: str, template: str) -> bool:
    """Compare a concrete request path against an OpenAPI-style template.

    '/identity/api/v2/vehicle/<vehicleid>/location' matches
    '/identity/api/v2/vehicle/8f1b.../location'. Placeholder segments — any
    segment wrapped in <> or {} — match any single segment.
    """
    if not finding_path or not template:
        return False
    a = [s for s in finding_path.strip("/").split("/") if s]
    b = [s for s in template.strip("/").split("/") if s]
    if len(a) != len(b):
        return False
    for seg_a, seg_b in zip(a, b):
        placeholder = (seg_b.startswith("<") and seg_b.endswith(">")) or \
                      (seg_b.startswith("{") and seg_b.endswith("}"))
        if placeholder:
            continue
        if seg_a != seg_b:
            return False
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir")
    ap.add_argument("--ground-truth", required=True)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    run_dir = Path(args.run_dir)
    gt = yaml.safe_load(open(args.ground_truth))
    findings = load_findings(run_dir)

    # A1 describes application-level vulnerabilities observable at runtime.
    # The pre-registered bounds allow only sast and dast (sca: 0, secrets: 0,
    # and no image bound at all). Dependency and OS-package CVEs that merely
    # share a CWE with a challenge are not detections of that challenge: a
    # CWE-200 advisory in a Debian library is unrelated to crAPI's documented
    # data-exposure endpoint. Whole families are therefore excluded BY
    # CONSTRUCTION, from the pre-registered bounds, rather than filtered after
    # inspecting results.
    ELIGIBLE_FAMILIES = {"sast", "dast"}
    excluded = [f for f in findings
                if FAMILY.get(f["tool"]) not in ELIGIBLE_FAMILIES]
    findings = [f for f in findings
                if FAMILY.get(f["tool"]) in ELIGIBLE_FAMILIES]

    # Endpoint matching on its own answers "did a tool touch this URL?", not
    # "did a tool find this vulnerability". Measured on this target: of the 45
    # DAST findings on /workshop/api/shop/orders, 44 are HTTP-protocol
    # observations (error codes, missing headers, unexpected content types) and
    # exactly one is a vulnerability. A finding therefore counts as an endpoint
    # detection only if it is substantive: severity MEDIUM or above, and not a
    # protocol-level observation.
    PROTOCOL_CWES = {"CWE-388", "CWE-693", "CWE-524", "CWE-497", "CWE-550",
                     "CWE-264", None}
    SUBSTANTIVE_SEVERITIES = {"MEDIUM", "HIGH", "CRITICAL"}

    def substantive(f):
        return (f.get("severity") in SUBSTANTIVE_SEVERITIES
                and f.get("cwe_id") not in PROTOCOL_CWES)

    results = []
    for ch in gt["challenges"]:
        cwe = ch.get("cwe")
        endpoint = ch.get("endpoint")

        strict = [f for f in findings if f.get("cwe_id") == cwe]
        by_endpoint = []
        if endpoint:
            by_endpoint = [f for f in findings
                           if substantive(f)
                           and endpoint_matches(path_of(f.get("location", "")),
                                                endpoint)]

        union = {f["raw_ref"]: f for f in strict + by_endpoint}.values()
        families = sorted({FAMILY.get(f["tool"], f["tool"]) for f in union})
        tools = sorted({f["tool"] for f in union})

        bound = ch.get("detectable_by", [])
        results.append({
            "id": ch["id"],
            "title": ch["title"],
            "cwe": cwe,
            "endpoint": endpoint,
            "nature": ch.get("nature"),
            "detected_strict": bool(strict),
            "detected_endpoint": bool(by_endpoint),
            "detected": bool(strict or by_endpoint),
            "findings_strict": len(strict),
            "findings_endpoint": len(by_endpoint),
            "by_family": families,
            "by_tool": tools,
            "bound": bound,
            "within_bound": set(families).issubset(set(bound)) if families else True,
            "sample": sorted({f.get("location", "") for f in union})[:5],
        })

    n = len(results)
    det_strict = sum(1 for r in results if r["detected_strict"])
    det_any = sum(1 for r in results if r["detected"])
    with_endpoint = sum(1 for r in results if r["endpoint"])

    bounds = gt.get("theoretical_upper_bound", {})
    family_recall = {}
    for fam, bound_n in bounds.items():
        detected = sum(1 for r in results if fam in r["by_family"])
        family_recall[fam] = {
            "detected": detected,
            "bound": bound_n,
            "recall": round(detected / bound_n, 3) if bound_n else None,
        }

    ext = gt.get("external_reference", {})
    report = {
        "run": run_dir.name,
        "ground_truth": gt["target"] + " A1",
        "commit": gt["commit"],
        "eligible_families": sorted(ELIGIBLE_FAMILIES),
        "endpoint_match_requires_substantive_finding": True,
        "protocol_cwes_excluded_from_endpoint_match": sorted(
            c for c in PROTOCOL_CWES if c),
        "findings_eligible": len(findings),
        "findings_excluded_by_family": len(excluded),
        "excluded_by_tool": dict(Counter(f["tool"] for f in excluded)),
        "challenges_total": n,
        "challenges_with_documented_endpoint": with_endpoint,
        "detected_strict_cwe": det_strict,
        "detected_any": det_any,
        "recall_strict": round(det_strict / n, 3),
        "recall_any": round(det_any / n, 3),
        "family_recall": family_recall,
        "external_reference": ext,
        "per_challenge": results,
    }

    out = Path(args.out) if args.out else run_dir / "evaluation-a1.json"
    out.write_text(json.dumps(report, indent=2))

    print(f"A1 recall — strict CWE: {det_strict}/{n} "
          f"({report['recall_strict']:.0%})  |  "
          f"CWE or endpoint: {det_any}/{n} ({report['recall_any']:.0%})")
    print(f"eligible families {sorted(ELIGIBLE_FAMILIES)}: "
          f"{len(findings)} findings considered, "
          f"{len(excluded)} excluded by construction")
    print(f"({with_endpoint}/{n} challenges document an endpoint; "
          f"endpoint matching is unavailable for the rest)\n")
    for r in results:
        flag = "OK " if r["detected"] else "MISS"
        how = []
        if r["detected_strict"]:
            how.append(f"cwe:{r['findings_strict']}")
        if r["detected_endpoint"]:
            how.append(f"endpoint:{r['findings_endpoint']}")
        print(f"  {flag} {r['id']}  {str(r['cwe']):<9} "
              f"{r['nature']:<15} {','.join(how) or '-':<22} "
              f"{','.join(r['by_tool']) or '-'}")
    print()
    for fam, v in family_recall.items():
        if v["bound"]:
            print(f"  {fam:<8} {v['detected']}/{v['bound']} "
                  f"({v['recall']:.0%} of pre-registered bound)")
    if ext:
        print(f"\n  external baseline — {ext.get('project')}: "
              f"{ext.get('detected')}/{ext.get('total')}")
    print(f"\nwritten: {out}")


if __name__ == "__main__":
    main()
