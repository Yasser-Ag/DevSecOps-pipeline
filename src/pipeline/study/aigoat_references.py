"""Build evaluation-only RAG references from preserved source and runtime evidence."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import tarfile

from study.coverage_registry import canonical, identity, summarize, validate


COMMIT = "e1c538badb93c6c1c2307096ab5d709a9ee0fe55"
SOURCE = "targets/aigoat/source/AIGoat-" + COMMIT
COLLECTION = "evidence/aigoat_qualification_2026-10-12/evidence"
RUN = COLLECTION + "/runtime-03"
BASE = "evidence/filtering_preflight_2026-09-23/attempt-02/development-v1/evaluation"
COLLECTION_HASH = "da18a21e477db5698805b55268fdd4c446db4c28562335eca86f02402765715b"
POPULATION = "aigoat-rag-context-authorization"
FAMILY = "aigoat:llm02-4"
ENDPOINT = "unauthorized owned-document inclusion in generation context"
UNIT = "document_actor_level_context_property"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def pointer(value, location):
    for part in location.lstrip("/").split("/") if location else ():
        part = part.replace("~1", "/").replace("~0", "~")
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


def expected_context(owner_id, actor_id, level):
    """Source-defined contract, not a label inferred from detector outcomes."""
    require(type(owner_id) is int and type(actor_id) is int, "Missing actor identity")
    require(type(level) is int and level in (0, 2), "Unqualified defense level")
    return owner_id == actor_id or level == 0


def inspect_trace(trace, document, expected):
    candidates = trace["candidates"]
    matches = [(i, c) for i, c in enumerate(candidates) if c["entry_id"] == document["id"]]
    require(bool(matches), "Reference document was not retrieved; do not score as protected")
    for _, chunk in matches:
        require(chunk["chunk_id"] == document["embedding_id"], "Chunk identity mismatch")
        require(chunk["content"] == document["content"], "Retrieved content mismatch")
        require(chunk["included_in_context"] is expected, "Context contract disagreement")
        require(chunk["truncated_by_budget"] is False, "Budget truncation is not ACL enforcement")
        require(chunk["excluded_by_control"] == (None if expected else "retrieval.acl"),
                "Unexpected exclusion mechanism")
    require(len(matches) == 1, "This qualified fixture contains one chunk per document")
    return matches[0]


def snapshot_rows(data):
    """Read selected public fixture fields; never extract or export credentials."""
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = archive.getmembers()
        selected = [m for m in members if m.name == "data/aigoat.db"]
        require(len(selected) == 1 and selected[0].isfile(), "Missing/ambiguous SQLite snapshot")
        require(selected[0].size <= 8 * 1024**2, "Unexpected snapshot size")
        require(not any(m.size and m.name in ("data/aigoat.db-wal", "data/aigoat.db-journal")
                        for m in members), "Snapshot needs journal reconciliation")
        database = archive.extractfile(selected[0]).read()
    connection = sqlite3.connect(":memory:")
    try:
        connection.deserialize(database)
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA query_only=ON")
        require(connection.execute("PRAGMA integrity_check").fetchone() == ("ok",), "Invalid database")
        actors = dict(connection.execute(
            "SELECT username, id FROM users WHERE username IN ('alice', 'bob')"))
        documents = {row[0]: {"id": row[0], "owner_id": row[1], "title": row[2],
                              "content": row[3], "content_hash": row[4], "embedding_id": row[5]}
                     for row in connection.execute(
                         "SELECT id, owner_id, title, content, content_hash, embedding_id "
                         "FROM knowledge_base_entries WHERE category='qualification'")}
        require(set(actors) == {"alice", "bob"} and len(set(actors.values())) == 2,
                "Two distinct fixture actors required")
        require(len(documents) == 2, "Unexpected qualification document population")
        return actors, documents, digest(database)
    finally:
        connection.close()


class Builder:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.inputs = {}

    def data(self, relative):
        path = (self.root / relative).resolve()
        require(path.is_relative_to(self.root), "Input escapes study root")
        data = path.read_bytes()
        self.inputs[relative] = {"path": relative, "sha256": digest(data), "bytes": len(data)}
        return data

    def read(self, relative):
        return json.loads(self.data(relative))

    def evidence(self, relative, location="", **extra):
        data = self.data(relative)
        if relative.endswith(".json"):
            pointer(json.loads(data), location)
        return {"path": relative, "sha256": digest(data), "pointer": location, **extra}

    def verify_inputs(self):
        manifest = self.data(COLLECTION + "/collection_manifest.json")
        require(digest(manifest) == COLLECTION_HASH, "Pinned collection manifest changed")
        for relative, expected in json.loads(manifest).items():
            data = self.data(COLLECTION + "/" + relative)
            require(len(data) == expected["bytes"] and digest(data) == expected["sha256"],
                    "Collected evidence changed: " + relative)
        source_manifest = self.read(COLLECTION + "/acquire-01/source_files.json")
        actual = {str(p.relative_to(self.root / SOURCE)) for p in (self.root / SOURCE).rglob("*")
                  if p.is_file()}
        require(actual == set(source_manifest), "Pinned source file inventory changed")
        for relative, expected in source_manifest.items():
            require(digest(self.data(SOURCE + "/" + relative)) == expected,
                    "Pinned target source changed: " + relative)

    def build(self, output):
        output = Path(output)
        require(not output.exists(), "Output already exists; preserve prior releases")
        self.verify_inputs()
        snapshot = RUN + "/qualified_state.tar.gz"
        actors, stored_docs, database_hash = snapshot_rows(self.data(snapshot))
        snapshot_evidence = self.evidence(snapshot, member="data/aigoat.db",
                                          member_sha256=database_hash,
                                          projection="users(id,username); qualification knowledge_base_entries")
        source_evidence = [
            self.evidence(SOURCE + "/config/labs/rag.yml", line_start=117, line_end=143),
            self.evidence(SOURCE + "/app/defense/controls/retrieval_acl.py", line_start=6, line_end=32),
            self.evidence(SOURCE + "/app/api/rag.py", line_start=321, line_end=347),
            self.evidence(SOURCE + "/app/rag/service.py", line_start=107, line_end=137),
            self.evidence(SOURCE + "/config/defense_profiles.yml", line_start=56, line_end=76),
        ]
        harness_evidence = self.evidence(RUN + "/controller/probe.py")
        kb = self.read(RUN + "/knowledge_base.json")["documents"]
        docs = {}
        for i, document in enumerate(kb):
            if document["category"] != "qualification":
                continue
            owner = next((name for name, uid in actors.items() if uid == document["owner_id"]), None)
            require(owner is not None and owner not in docs, "Unexpected/duplicate document owner")
            created = self.read(RUN + "/document_" + owner + ".json")
            require("owner_id" not in created["request"], "Ownership was explicitly overridden")
            require(created["response"]["id"] == document["id"], "Created document identity changed")
            for field in ("title", "content", "category", "trust_tier"):
                require(created["request"][field] == document[field], "Created content changed")
            require(document["content_hash"] == digest((document["title"] + "\n" + document["content"]).encode()),
                    "Document content hash mismatch")
            for field, value in stored_docs[document["id"]].items():
                require(document[field] == value, "Database/API document mismatch: " + field)
            docs[owner] = (document, self.evidence(RUN + "/knowledge_base.json", f"/documents/{i}"))
        require(set(docs) == set(actors), "Incomplete directional fixtures")

        references, observations, nodes, relations = [], [], [], []
        for owner, (document, doc_evidence) in sorted(docs.items()):
            doc_node = identity("artifact-", COMMIT, "runtime-03", "document", document["id"])
            chunk_node = identity("artifact-", COMMIT, "runtime-03", "chunk", document["embedding_id"])
            nodes.extend([
                {"id": doc_node, "kind": "database_document", "document_id": document["id"],
                 "owner_id": document["owner_id"], "content_sha256": digest(document["content"].encode()),
                 "evidence": [doc_evidence, snapshot_evidence]},
                {"id": chunk_node, "kind": "retrieval_chunk", "chunk_id": document["embedding_id"],
                 "evidence": [doc_evidence]},
            ])
            relations.append({"source_id": chunk_node, "target_id": doc_node,
                              "relation": "chunk_of", "evidence": [doc_evidence], "is_equality": False})
            for actor, actor_id in sorted(actors.items()):
                for level in (0, 2):
                    key = f"{owner}-document-{actor}-L{level}"
                    case_id = identity("case-", COMMIT, "runtime-03", ENDPOINT, document["id"], actor_id, level)
                    expected = expected_context(document["owner_id"], actor_id, level)
                    truth = "positive" if actor_id != document["owner_id"] and expected else "negative"
                    trace_path = RUN + "/trace_" + key + ".json"
                    trace = self.read(trace_path)
                    require(trace["request"] == {"query": f"What is the private qualification coupon for {owner.title()}?",
                                                 "defense_level": level, "top_k": 5, "hybrid": False},
                            "Unqualified request parameters")
                    index, chunk = inspect_trace(trace["response"], document, expected)
                    trace_evidence = self.evidence(trace_path, f"/response/candidates/{index}")
                    references.append({
                        "case_id": case_id, "population": POPULATION, "unit": UNIT, "endpoint": ENDPOINT,
                        "truth": truth, "object_id": doc_node, "family_id": FAMILY,
                        "source_reference_id": FAMILY + ":" + key,
                        "evidence": source_evidence + [doc_evidence, snapshot_evidence, trace_evidence, harness_evidence],
                        "details": {"commit": COMMIT, "run_id": "runtime-03", "actor": actor,
                                    "actor_id": actor_id, "document_id": document["id"],
                                    "owner_id": document["owner_id"], "defense_level": level,
                                    "expected_in_context": expected,
                                    "label_basis": "source-defined ownership contract; runtime checked",
                                    "coauthor_review": "pending", "scanner_used_as_oracle": False,
                                    "split_role": "development_after_outcome_access",
                                    "scope": "Named document and prompt-context boundary only; not whole-application confidentiality"},
                    })
                    nodes.append({"id": case_id, "kind": "reference_case"})
                    relations.append({"source_id": case_id, "target_id": doc_node,
                                      "relation": "authorization_property_of", "evidence": [doc_evidence],
                                      "is_equality": False})
                    observation_id = identity("observation-", key, "retrieval", "runtime-03", COMMIT)
                    observations.append({"observation_id": observation_id, "case_id": case_id,
                                         "kind": "reference_retrieval_probe", "scanner_detection": False,
                                         "retrieved": True, "included_in_context": expected,
                                         "excluded_by_control": chunk["excluded_by_control"],
                                         "evidence": [trace_evidence, harness_evidence]})
                    nodes.append({"id": observation_id, "kind": "reference_retrieval_probe"})
                    relations.append({"source_id": observation_id, "target_id": case_id,
                                      "relation": "observes_context_property", "evidence": [trace_evidence],
                                      "is_equality": False})
                    if owner == "alice":
                        generation_path = RUN + "/generation_" + key + ".json"
                        generation = self.read(generation_path)
                        require(generation["request"]["input"] == {
                            "message": "What is the private qualification coupon for Alice?", "use_kb": True,
                            "defense_level": level, "top_k": 5, "hybrid": False}, "Generation request changed")
                        result = generation["response"]["result"]
                        included = [c for c in result["context_used"] if c["entry_id"] == document["id"]]
                        require(bool(included) == expected, "Generation context disagrees with contract")
                        for c in included:
                            require(c["content"] == document["content"] and c["owner_id"] == document["owner_id"],
                                    "Generation document identity mismatch")
                        require(result["reply"].strip() and result["reply"] != "I couldn't process that request.",
                                "Generation failed or used fallback")
                        generation_evidence = self.evidence(generation_path, "/response/result")
                        generation_id = identity("observation-", key, "generation", "runtime-03", COMMIT)
                        observations.append({"observation_id": generation_id, "case_id": case_id,
                                             "kind": "reference_generation_probe", "scanner_detection": False,
                                             "included_in_context": bool(included),
                                             "marker_emitted": "ALICEQUAL20261012" in result["reply"],
                                             "elapsed_seconds": generation["elapsed_seconds"],
                                             "marker_scope": "Observed single response; not a reference label or success-rate estimate",
                                             "evidence": [generation_evidence, harness_evidence]})
                        nodes.append({"id": generation_id, "kind": "reference_generation_probe"})
                        relations.append({"source_id": generation_id, "target_id": case_id,
                                          "relation": "observes_generation_for", "evidence": [generation_evidence],
                                          "is_equality": False})

        population = {"population": POPULATION, "layer": "rag-authorization",
                      "cohort": "One AIGoat scenario; two supplied documents; two users; levels 0/2",
                      "endpoint": ENDPOINT, "unit": UNIT,
                      "linkage_status": "scanner_qualification_and_coauthor_review_pending"}
        originals = {name: self.data(BASE + "/" + name) for name in
                     ("references.jsonl", "native_findings.jsonl", "links.jsonl", "populations.json")}
        parse_lines = lambda value: [json.loads(line) for line in value.splitlines()]
        old_refs = parse_lines(originals["references.jsonl"])
        findings = parse_lines(originals["native_findings.jsonl"])
        links = parse_lines(originals["links.jsonl"])
        populations = json.loads(originals["populations.json"]) + [population]
        validate(old_refs + references, findings, links, populations)
        ledger = summarize(old_refs + references, findings, links, populations)
        new_ledger = next(p for p in ledger if p["population"] == POPULATION)
        require(new_ledger["reference_coverage"] is None, "Pending scanner qualification became zero recall")
        node_ids = {node["id"] for node in nodes}
        require(len(node_ids) == len(nodes), "Duplicate graph identity")
        require(all(edge["source_id"] in node_ids and edge["target_id"] in node_ids for edge in relations),
                "Dangling artifact relation")

        output.mkdir(parents=True, exist_ok=False)
        (output / "evaluation").mkdir()
        for name, rows in [("rag_references.jsonl", references), ("reference_observations.jsonl", observations),
                           ("artifact_nodes.jsonl", nodes), ("artifact_relations.jsonl", relations)]:
            (output / name).write_text("".join(canonical(row) + "\n" for row in rows))
        (output / "evaluation/references.jsonl").write_bytes(
            originals["references.jsonl"] + "".join(canonical(row) + "\n" for row in references).encode())
        for name in ("native_findings.jsonl", "links.jsonl"):
            (output / "evaluation" / name).write_bytes(originals[name])
        for name, value in [("evaluation/populations.json", populations), ("coverage_by_population.json", ledger)]:
            (output / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
        summary = {
            "schema_version": "aigoat-reference-development-1", "stage": "local_saved_evidence_replay",
            "source_commit": COMMIT, "reference_cases": len(references), "weakness_families": 1,
            "documents": len(docs), "label_counts": dict(Counter(r["truth"] for r in references)),
            "observations": dict(Counter(o["kind"] for o in observations)),
            "artifact_relations": len(relations), "combined_reference_records": len(old_refs) + len(references),
            "unchanged_native_warnings": len(findings), "unchanged_finding_case_links": len(links),
            "rag_scanner_coverage": None, "coauthor_review": "pending",
            "models_invoked": False, "scanners_invoked": False, "remote_access_performed": False,
            "qualification_manifest_sha256": COLLECTION_HASH,
            "evaluation_only": True, "safe_for_inference_mount": False,
            "limitations": ["No new scanner detection or false-positive label.",
                            "Directional controls share one scenario and are not independent defects.",
                            "Request actor follows the preserved harness; raw authentication tokens are not exported.",
                            "Trace and transcript responses retain excluded document content.",
                            "Defense level is caller-selected in this teaching application; level 2 is not a deployment-wide guarantee.",
                            "API-projected context plus pinned source supports the prompt-construction link; raw model input was not independently captured.",
                            "Source, container, and document identities are not automatically equivalent.",
                            "All cases were observed during development and are excluded from claims of unseen final evaluation."],
            "inputs": [self.inputs[key] for key in sorted(self.inputs)],
            "outputs": [{"path": str(p.relative_to(output)), "sha256": digest(p.read_bytes()),
                         "bytes": p.stat().st_size} for p in sorted(output.rglob("*")) if p.is_file()],
        }
        (output / "manifest.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
        return {k: v for k, v in summary.items() if k not in ("inputs", "outputs", "limitations")}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(Builder(args.root).build(args.output), indent=2))
