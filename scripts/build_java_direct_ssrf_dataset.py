#!/usr/bin/env python3
"""Build a Java Direct SSRF dataset from the local advisory database.

The script intentionally splits the workflow into two phases:

1. candidate identification
2. code evidence extraction

It only seeds candidates from the local advisory database. Network access is
used only after a local advisory has been identified and recorded.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
ADVISORY_ROOT = REPO_ROOT / "advisory-database" / "advisories"
OUTPUT_DIR = REPO_ROOT / "outputs"

USER_AGENT = "java-direct-ssrf-dataset-builder/1.0"

SSRF_PATTERNS = (
    "ssrf",
    "server-side request forgery",
    "server side request forgery",
)

JAVA_HINT_PATTERNS = (
    "src/main/java",
    "src\\main\\java",
    ".java",
    "maven",
    "spring",
    "servlet",
    "jsp",
    " apache ofbiz",
    " gocd",
    " xxl-job",
    " jeesite",
    " easy-admin",
    " bytedesk",
    "java ",
)

DIRECT_SSRF_HINTS = (
    "argument url",
    "parameter url",
    "proxy",
    "http request",
    "make http requests",
    "request handler",
    "thumbnail",
    "avatar",
    "favicon",
    "fetch",
    "pipeline",
    "endpoint",
    "metadata",
    "outbound",
    "relay",
    "arbitrary origins",
    "arbitrary network requests",
)

DROP_ONLY_HINTS = (
    "xml external entity",
    "xxe",
    "browser",
    "user clicks",
    "client for meetings",
    "chat’s",
    "chat's",
)

VALIDATOR_API_HINTS = (
    "urlvalidator",
    "isvalidurl",
    "startswith(",
    "contains(",
    "matches(",
    "pattern",
    "new url(",
    "uri.create(",
    ".gethost(",
    "allowlist",
    "whitelist",
    "blacklist",
)

REQUESTER_API_HINTS = (
    "httpclient",
    "urlconnection",
    "resttemplate",
    "webclient",
    "jsoup.connect",
    "imageio.read",
    "thumbnails.of",
    ".execute(",
    "compressbysize(",
    "new url(",
)

SUPPORTED_BRIDGE_REPOSITORIES = {
    "https://github.com/apache/ofbiz-framework",
    "https://github.com/gocd/gocd",
    "https://github.com/xuxueli/xxl-job",
}


@dataclass
class Candidate:
    advisory_path: str
    case_id: str
    project: str
    package: str
    java_direct_ssrf: str
    evidence_strength: str
    repeat_fix_signal: str
    keep_or_drop: str
    reason: str
    advisory: dict[str, Any]
    advisory_urls: list[str] = field(default_factory=list)
    repository: str = ""
    aliases: list[str] = field(default_factory=list)
    reference_urls: list[str] = field(default_factory=list)
    repeat_markers: list[str] = field(default_factory=list)
    supported_for_code_extraction: bool = False
    code_evidence: dict[str, Any] | None = None


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def fetch_text(url: str, timeout: int = 30) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        charset = response.headers.get_content_charset() or "utf-8"
        return response.read().decode(charset, "ignore")


def run_git(args: list[str], cwd: Path | None = None, timeout: int | None = None) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=str(cwd) if cwd else None,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )
    return completed.stdout


def run_command(args: list[str], cwd: Path | None = None, timeout: int | None = None) -> str:
    completed = subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )
    return completed.stdout


def advisory_text(advisory: dict[str, Any]) -> str:
    parts = [advisory.get("details", "")]
    parts.extend(ref.get("url", "") for ref in advisory.get("references", []))
    for affected in advisory.get("affected", []):
        package = affected.get("package", {})
        parts.append(package.get("ecosystem", ""))
        parts.append(package.get("name", ""))
    return "\n".join(part for part in parts if part)


def contains_ssrf_signal(text: str) -> bool:
    lowered = text.lower()
    return any(pattern in lowered for pattern in SSRF_PATTERNS)


def java_leaning(advisory: dict[str, Any], text: str) -> bool:
    for affected in advisory.get("affected", []):
        package = affected.get("package", {})
        ecosystem = (package.get("ecosystem") or "").lower()
        if ecosystem == "maven":
            return True
    lowered = text.lower()
    return any(pattern in lowered for pattern in JAVA_HINT_PATTERNS)


def classify_direct_ssrf(advisory: dict[str, Any], text: str) -> tuple[str, str]:
    lowered = text.lower()
    refs = [ref.get("url", "") for ref in advisory.get("references", []) if ref.get("url")]
    if not java_leaning(advisory, text):
        return "no", "drop: not confidently Java/Maven"
    if any(pattern in lowered for pattern in DROP_ONLY_HINTS):
        if "xxe" in lowered or "xml external entity" in lowered:
            return "no", "drop: XXE/XML parsing case, not direct SSRF"
        return "no", "drop: client-side or user-driven request flow"
    if any(pattern in lowered for pattern in DIRECT_SSRF_HINTS):
        return "yes", "keep-candidate: Java-leaning SSRF with direct outbound request signal"
    if "apache ofbiz" in lowered and any(token in lowered for token in SSRF_PATTERNS):
        return "yes", "keep-candidate: official Apache OFBiz SSRF advisory with bridgeable issue/release evidence"
    if "gocd" in lowered and any(token in lowered for token in SSRF_PATTERNS):
        return "yes", "keep-candidate: official GoCD SSRF advisory with bridgeable repository evidence"
    if any("issues.apache.org/jira/browse/ofbiz-" in url.lower() for url in refs):
        return "yes", "keep-candidate: Java-leaning SSRF advisory with official OFBiz issue linkage"
    if "allows ssrf" in lowered or "vulnerable to server-side request forgery" in lowered:
        return "yes", "keep-candidate: advisory explicitly states SSRF in a Java-leaning project"
    return "no", "drop: SSRF wording present but direct outbound request signal is weak"


def normalize_repo_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    path = parsed.path.rstrip("/")
    if "/commit/" in path:
        path = path.split("/commit/")[0]
    elif "/pull/" in path:
        path = path.split("/pull/")[0]
    elif "/compare/" in path:
        path = path.split("/compare/")[0]
    elif "/issues/" in path:
        path = path.split("/issues/")[0]
    elif "/security/" in path:
        path = path.split("/security/")[0]
    elif "/blob/" in path:
        path = path.split("/blob/")[0]
    elif "/tree/" in path:
        path = path.split("/tree/")[0]
    if parsed.netloc == "gitlab.com" and "/-/" in path:
        path = path.split("/-/")[0]
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))


def to_git_clone_url(url: str) -> str:
    if url.endswith(".git"):
        return url
    return f"{url}.git"


def commit_hash_from_url(url: str) -> str:
    match = re.search(r"/commit/([0-9a-fA-F]{7,40})", url)
    return match.group(1) if match else ""


def issue_key_from_url(url: str) -> str:
    match = re.search(r"/browse/([A-Z]+-\d+)", url)
    return match.group(1) if match else ""


def parse_project_name(advisory: dict[str, Any], refs: list[str]) -> str:
    for affected in advisory.get("affected", []):
        package = affected.get("package", {})
        name = package.get("name")
        if name:
            return name.split(":")[0]
    for url in refs:
        parsed = urllib.parse.urlparse(url)
        bits = [bit for bit in parsed.path.split("/") if bit]
        if parsed.netloc in {"github.com", "gitee.com", "gitlab.com"} and len(bits) >= 2:
            return bits[1]
    details = advisory.get("details", "")
    for pattern in (
        r"in ([A-Z][A-Za-z0-9 ._-]+?) before",
        r"^([A-Z][A-Za-z0-9 ._-]+?) [0-9]",
        r"^Adding a new pipeline in ([A-Z][A-Za-z0-9 ._-]+?) ",
    ):
        match = re.search(pattern, details)
        if match:
            return match.group(1).strip()
    return advisory.get("id", "")


def parse_package_name(advisory: dict[str, Any], project: str) -> str:
    for affected in advisory.get("affected", []):
        package = affected.get("package", {})
        name = package.get("name")
        if name:
            return name
    return project


def derive_repository(advisory: dict[str, Any], refs: list[str], project: str) -> str:
    for url in refs:
        parsed = urllib.parse.urlparse(url)
        if parsed.netloc in {"github.com", "gitee.com", "gitlab.com"}:
            return normalize_repo_url(url)
    details = (advisory.get("details") or "").lower()
    combined = details + "\n" + "\n".join(refs).lower()
    if "apache ofbiz" in combined or "ofbiz.apache.org" in combined or "ofbiz-" in combined:
        return "https://github.com/apache/ofbiz-framework"
    if "gocd" in combined:
        return "https://github.com/gocd/gocd"
    if "xxl-job" in combined:
        return "https://github.com/xuxueli/xxl-job"
    return ""


def infer_evidence_strength(refs: list[str], repository: str) -> str:
    has_direct_commit = any("/commit/" in url for url in refs)
    has_direct_pr = any("/pull/" in url or "/merge_requests/" in url for url in refs)
    has_issue_or_release = any(
        token in url
        for url in refs
        for token in ("/issues/", "/browse/", "security.html", "release-notes", "releases/tag", "download.html")
    )
    if has_direct_commit or has_direct_pr:
        return "high"
    if repository and has_issue_or_release:
        return "medium"
    if repository:
        return "low"
    return "low"


def has_direct_fix_artifact(refs: list[str]) -> bool:
    return any(token in url for url in refs for token in ("/commit/", "/compare/"))


def supports_bridge_strategy(repository: str, refs: list[str]) -> bool:
    if repository in SUPPORTED_BRIDGE_REPOSITORIES:
        return any(token in url for url in refs for token in ("/browse/", "/issues/", "security.html", "release-notes", "download.html"))
    return False


def infer_repeat_markers(advisory: dict[str, Any], refs: list[str]) -> list[str]:
    text = (advisory.get("details") or "").lower()
    markers = []
    for token in ("incomplete fix", "similar, but not identical", "similar but not identical", "same vulnerability"):
        if token in text:
            markers.append(token)
    alias_text = " ".join(advisory.get("aliases", []))
    if re.search(r"CVE-\d{4}-\d+", alias_text) and "through" in text:
        markers.append("multi-cve-wording")
    if any("/issues/" in url and "#issuecomment-" in url for url in refs):
        markers.append("issue-thread-followup")
    return markers


def infer_repeat_signal(markers: list[str]) -> str:
    if not markers:
        return "low"
    if any(marker in markers for marker in ("incomplete fix", "same vulnerability")):
        return "high"
    return "medium"


def find_ssrf_json_paths(advisory_root: Path) -> list[Path]:
    pattern = "ssrf|server-side request forgery|server side request forgery"
    try:
        output = run_command(
            [
                "grep",
                "-R",
                "-l",
                "--include=*.json",
                "-i",
                "-E",
                pattern,
                str(advisory_root),
            ],
            timeout=120,
        )
    except subprocess.CalledProcessError as exc:
        if exc.returncode == 1:
            return []
        raise
    paths = []
    for line in output.splitlines():
        if line.strip():
            paths.append(Path(line.strip()).resolve())
    return sorted(paths)


def find_candidate_advisories(advisory_root: Path) -> list[Candidate]:
    advisory_root = advisory_root.resolve()
    candidates: list[Candidate] = []
    for json_path in find_ssrf_json_paths(advisory_root):
        advisory = load_json(json_path)
        combined_text = advisory_text(advisory)
        references = [ref.get("url", "") for ref in advisory.get("references", []) if ref.get("url")]
        project = parse_project_name(advisory, references)
        package = parse_package_name(advisory, project)
        repository = derive_repository(advisory, references, project)
        java_direct_ssrf, reason = classify_direct_ssrf(advisory, combined_text)
        evidence_strength = infer_evidence_strength(references, repository)
        repeat_markers = infer_repeat_markers(advisory, references)
        repeat_fix_signal = infer_repeat_signal(repeat_markers)
        keep_or_drop = "drop"
        if java_direct_ssrf == "yes":
            if has_direct_fix_artifact(references):
                keep_or_drop = "keep"
            elif supports_bridge_strategy(repository, references):
                keep_or_drop = "keep"
        advisory_path = str(json_path.resolve().relative_to(REPO_ROOT))
        advisory_urls = [url for url in references if "CVE-" in url or "GHSA" in url or "security" in url or "nvd.nist.gov" in url]
        candidates.append(
            Candidate(
                advisory_path=advisory_path,
                case_id=advisory.get("id", advisory_path),
                project=project,
                package=package,
                java_direct_ssrf=java_direct_ssrf,
                evidence_strength=evidence_strength,
                repeat_fix_signal=repeat_fix_signal,
                keep_or_drop=keep_or_drop,
                reason=reason,
                advisory=advisory,
                advisory_urls=advisory_urls,
                repository=repository,
                aliases=advisory.get("aliases", []),
                reference_urls=references,
                repeat_markers=repeat_markers,
            )
        )
    return candidates


def clone_repo(repo_url: str, base_dir: Path) -> Path:
    target = base_dir / re.sub(r"[^A-Za-z0-9._-]+", "_", repo_url)
    if target.exists():
        return target
    run_git(["clone", "--filter=blob:none", to_git_clone_url(repo_url), str(target)], timeout=90)
    return target


def search_commit_in_repo(repo_path: Path, search_terms: Iterable[str]) -> list[str]:
    terms = [term for term in search_terms if term]
    if not terms:
        return []
    commits = []
    seen = set()
    for term in terms:
        try:
            output = run_git(
                ["log", "--oneline", "--all", "--regexp-ignore-case", f"--grep={term}", "-n", "10"],
                cwd=repo_path,
                timeout=60,
            )
        except subprocess.CalledProcessError:
            continue
        for line in output.splitlines():
            if not line.strip():
                continue
            commit = line.split()[0]
            if commit in seen:
                continue
            seen.add(commit)
            commits.append(commit)
    return commits


def extract_issue_summary(issue_url: str) -> str:
    try:
        body = fetch_text(issue_url)
    except Exception:
        return ""
    key = issue_key_from_url(issue_url)
    if key:
        match = re.search(rf"{re.escape(key)}\]\s+\[SECURITY\]\s+(.*?)(?:<|\n)", body, re.IGNORECASE | re.DOTALL)
        if match:
            summary = html.unescape(match.group(1)).strip()
            summary = re.sub(r"\s+-\s+ASF Jira.*$", "", summary, flags=re.IGNORECASE)
            return summary.strip(' "\'/')
    title_match = re.search(r"<title>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    if title_match:
        summary = html.unescape(title_match.group(1)).strip()
        summary = re.sub(r"\s+-\s+ASF Jira.*$", "", summary, flags=re.IGNORECASE)
        summary = re.sub(r"<.*$", "", summary)
        return summary.strip(' "\'/')
    return ""


def find_fix_artifacts(candidate: Candidate, repo_cache: Path) -> dict[str, Any]:
    refs = candidate.reference_urls
    commit_urls = [url for url in refs if "/commit/" in url]
    repository = candidate.repository
    evidence: dict[str, Any] = {
        "repository": repository,
        "direct_artifact_urls": commit_urls[:],
        "bridge_inputs": [],
        "bridged_commits": [],
        "official_refs_used": [],
        "fix_evidence_missing": False,
    }
    if not repository:
        evidence["fix_evidence_missing"] = True
        return evidence

    commits: list[str] = [commit_hash_from_url(url) for url in commit_urls if commit_hash_from_url(url)]
    evidence["official_refs_used"].extend(commit_urls)
    if commits:
        evidence["commit_role_map"] = {commit: "primary_fix" if idx == 0 else "unknown" for idx, commit in enumerate(commits)}
        return evidence | {"commits": commits}

    issue_refs = [url for url in refs if "/issues/" in url or "/browse/" in url]
    release_refs = [url for url in refs if "release" in url or "security.html" in url or "download.html" in url]
    repo_path = clone_repo(repository, repo_cache)

    search_terms: list[str] = []
    search_terms.extend(candidate.aliases)
    search_terms.append(candidate.case_id)

    for issue_url in issue_refs:
        issue_key = issue_key_from_url(issue_url)
        summary = extract_issue_summary(issue_url)
        evidence["bridge_inputs"].append({"issue_url": issue_url, "issue_key": issue_key, "summary": summary})
        if issue_key:
            search_terms.append(issue_key)
        if summary:
            search_terms.append(summary)
            search_terms.append(re.sub(r"^\(CVE-[^)]+\)\s*", "", summary, flags=re.IGNORECASE))
            summary_words = summary.split()
            if len(summary_words) >= 6:
                search_terms.append(" ".join(summary_words[:8]))
            if "component://" in summary:
                search_terms.append("starts with component://")

    for release_url in release_refs:
        evidence["bridge_inputs"].append({"release_url": release_url})

    bridged_commits = search_commit_in_repo(repo_path, search_terms)
    if bridged_commits:
        evidence["bridged_commits"] = bridged_commits
        evidence["official_refs_used"].extend(issue_refs or release_refs)
        evidence["commit_role_map"] = {commit: "primary_fix" if idx == 0 else "unknown" for idx, commit in enumerate(bridged_commits)}
        return evidence | {"commits": bridged_commits}

    evidence["fix_evidence_missing"] = True
    return evidence | {"commits": []}


def parse_diff_hunks(diff_text: str) -> list[dict[str, Any]]:
    hunks: list[dict[str, Any]] = []
    current_file = ""
    lines = diff_text.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        if line.startswith("diff --git "):
            current_file = ""
        elif line.startswith("+++ b/"):
            current_file = line[6:]
        elif line.startswith("@@ "):
            header = line
            body: list[str] = []
            index += 1
            while index < len(lines):
                nxt = lines[index]
                if nxt.startswith("diff --git ") or nxt.startswith("@@ "):
                    index -= 1
                    break
                body.append(nxt)
                index += 1
            hunks.append({"file": current_file, "header": header, "body": body})
        index += 1
    return hunks


def trim_snippet(lines: list[str], minimum: int = 5, maximum: int = 20) -> str:
    cleaned = [line for line in lines if line != "\\ No newline at end of file"]
    if len(cleaned) > maximum:
        cleaned = cleaned[:maximum]
    if len(cleaned) < minimum:
        cleaned = cleaned[:minimum]
    return "\n".join(cleaned).strip()


def infer_method_name(header: str, before_code: str, after_code: str) -> str:
    if "@@" in header:
        tail = header.split("@@", 2)[-1].strip()
        if tail:
            return tail
    combined = "\n".join([before_code, after_code])
    signature = re.findall(r"(public|private|protected)\s+[^\n{]+\(", combined)
    if signature:
        return signature[-1]
    return "UNKNOWN"


def pick_relevant_hunk(hunks: list[dict[str, Any]]) -> dict[str, Any] | None:
    scored: list[tuple[int, dict[str, Any]]] = []
    for hunk in hunks:
        if not hunk["file"].endswith(".java"):
            continue
        body_text = "\n".join(hunk["body"]).lower()
        score = 0
        if "/test/" in hunk["file"].lower():
            score -= 5
        for token in ("url", "http", "host", "allow", "component://", "thumbnail", "proxy", "ssrf"):
            if token in body_text:
                score += 2
        if any(line.startswith("+") for line in hunk["body"]) and any(line.startswith("-") for line in hunk["body"]):
            score += 3
        scored.append((score, hunk))
    if not scored:
        return None
    scored.sort(key=lambda item: item[0], reverse=True)
    return scored[0][1]


def summarize_pattern(before_code: str, after_code: str) -> str:
    before_lower = before_code.lower()
    after_lower = after_code.lower()
    if "contains(\"component://\")" in before_lower and "startswith(\"component://\")" in after_lower:
        return "Tighten the component-path guard by requiring the trusted prefix at the start of the string instead of accepting the token anywhere in the input."
    if "startswith(\"http://\")" in after_lower or "startswith(\"https://\")" in after_lower:
        if "allowlist" in after_lower or "getallowlist" in after_lower or ".gethost()" in after_lower:
            return "Add protocol checks and host allowlist validation before passing the user-controlled URL into the image-fetch path."
        return "Add explicit scheme validation before the code reaches the outbound request path."
    if ".gethost()" in after_lower and ".gethost()" not in before_lower:
        return "Parse the supplied URL and validate the resolved host before continuing to the downstream fetch logic."
    return "Tighten validation around the user-controlled target before the code reaches the outbound request path."


def summarize_ambiguity(before_code: str, after_code: str) -> dict[str, Any]:
    before_lower = before_code.lower()
    after_lower = after_code.lower()
    combined = before_lower + "\n" + after_lower
    has_validator = any(token in combined for token in VALIDATOR_API_HINTS)
    has_requester = any(token in combined for token in REQUESTER_API_HINTS)
    if not (has_validator and has_requester):
        return {
            "exists": False,
            "summary": "UNKNOWN",
            "validator_side": {"api_family": "UNKNOWN", "apis": [], "semantic_use": "UNKNOWN"},
            "requester_side": {"api_family": "UNKNOWN", "apis": [], "semantic_use": "UNKNOWN"},
            "evidence": [],
        }
    validator_apis = [token for token in VALIDATOR_API_HINTS if token in combined]
    requester_apis = [token for token in REQUESTER_API_HINTS if token in combined]
    summary = "The fix shows validator logic and outbound request logic side by side, so the validator semantics must match how the downstream requester interprets the same user-controlled target."
    return {
        "exists": True,
        "summary": summary,
        "validator_side": {
            "api_family": "input_validation",
            "apis": validator_apis,
            "semantic_use": "Validation happens before the outbound request path.",
        },
        "requester_side": {
            "api_family": "request_dispatch",
            "apis": requester_apis,
            "semantic_use": "These calls or helpers consume the validated value on the request path.",
        },
        "evidence": [],
    }


def extract_code_evidence(candidate: Candidate, repo_cache: Path) -> dict[str, Any] | None:
    fix_artifacts = find_fix_artifacts(candidate, repo_cache)
    commits = fix_artifacts.get("commits", [])
    if not commits or fix_artifacts.get("fix_evidence_missing"):
        return {
            "fix_artifacts": fix_artifacts,
            "fix_evidence_missing": True,
        }

    repo_path = clone_repo(candidate.repository, repo_cache)
    evidences = []
    fix_commits = []
    for index, commit in enumerate(commits):
        diff_text = run_git(["show", "--unified=12", commit, "--", "*.java"], cwd=repo_path, timeout=60)
        hunks = parse_diff_hunks(diff_text)
        hunk = pick_relevant_hunk(hunks)
        if not hunk:
            continue
        before_lines = [line[1:] for line in hunk["body"] if line[:1] in {" ", "-"}]
        after_lines = [line[1:] for line in hunk["body"] if line[:1] in {" ", "+"}]
        before_code = trim_snippet(before_lines)
        after_code = trim_snippet(after_lines)
        method = infer_method_name(hunk["header"], before_code, after_code)
        pattern_summary = summarize_pattern(before_code, after_code)
        ambiguity = summarize_ambiguity(before_code, after_code)
        if ambiguity["exists"]:
            ambiguity["evidence"].append(
                {
                    "commit": commit,
                    "file": hunk["file"],
                    "method": method,
                    "before_code": before_code,
                    "after_code": after_code,
                    "semantic_delta": ambiguity["summary"],
                    "why_it_matters": "Validator-side and requester-side semantics are both visible in the changed code path.",
                }
            )
        evidences.append(
            {
                "commit": commit,
                "file": hunk["file"],
                "method": method,
                "before_code": before_code,
                "after_code": after_code,
                "inferred_pattern": pattern_summary,
                "why_it_matters": "This is the closest changed Java hunk tying the fix to the SSRF-relevant code path.",
            }
        )
        fix_commits.append(
            {
                "commit": commit,
                "role": fix_artifacts.get("commit_role_map", {}).get(commit, "unknown") if index == 0 else "unknown",
                "commit_url": next((url for url in candidate.reference_urls if commit in url), f"{candidate.repository}/commit/{commit}"),
                "summary": pattern_summary,
            }
        )

    if not evidences:
        return {
            "fix_artifacts": fix_artifacts,
            "fix_evidence_missing": True,
        }

    ambiguity = summarize_ambiguity(evidences[0]["before_code"], evidences[0]["after_code"])
    unknown_fields = []
    if not ambiguity["exists"]:
        unknown_fields.append("ambiguity_rule_inferred_from_commit")

    return {
        "fix_artifacts": fix_artifacts,
        "fix_evidence_missing": False,
        "fix_commits": fix_commits,
        "repair_pattern": {
            "summary": evidences[0]["inferred_pattern"],
            "evidence": evidences,
        },
        "ambiguity_rule": ambiguity,
        "unknown_fields": unknown_fields,
    }


def build_repeat_relations(candidates: list[Candidate]) -> dict[str, dict[str, Any]]:
    commit_to_case_ids: dict[str, list[str]] = defaultdict(list)
    repo_to_case_ids: dict[str, list[str]] = defaultdict(list)
    for candidate in candidates:
        if candidate.code_evidence and not candidate.code_evidence.get("fix_evidence_missing"):
            for commit in candidate.code_evidence.get("fix_commits", []):
                commit_to_case_ids[commit["commit"]].append(candidate.case_id)
        if candidate.repository:
            repo_to_case_ids[candidate.repository].append(candidate.case_id)

    relations: dict[str, dict[str, Any]] = {}
    for candidate in candidates:
        previous_case_ids: list[str] = []
        evidence_urls: list[str] = []
        description = ""
        if candidate.code_evidence and not candidate.code_evidence.get("fix_evidence_missing"):
            for commit in candidate.code_evidence.get("fix_commits", []):
                siblings = [case_id for case_id in commit_to_case_ids[commit["commit"]] if case_id != candidate.case_id]
                if siblings:
                    previous_case_ids.extend(siblings)
                    evidence_urls.append(commit["commit_url"])
                    description = "Same fix commit is referenced by multiple SSRF advisories in the same repository."
        if not previous_case_ids and candidate.repeat_markers:
            siblings = [case_id for case_id in repo_to_case_ids[candidate.repository] if case_id != candidate.case_id]
            if siblings:
                previous_case_ids.extend(siblings[:5])
                evidence_urls.extend(candidate.reference_urls[:3])
                description = "Advisory wording signals a repeated or incomplete-fix family within the same repository."
        relations[candidate.case_id] = {
            "exists": bool(previous_case_ids),
            "previous_case_ids": sorted(set(previous_case_ids)),
            "description": description,
            "evidence_urls": sorted(set(evidence_urls)),
        }
    return relations


def candidate_row(candidate: Candidate) -> str:
    values = [
        candidate.advisory_path,
        candidate.case_id,
        candidate.project,
        candidate.package,
        candidate.java_direct_ssrf,
        candidate.evidence_strength,
        candidate.repeat_fix_signal,
        candidate.keep_or_drop,
        candidate.reason,
    ]
    escaped = [value.replace("|", "\\|") for value in values]
    return "| " + " | ".join(escaped) + " |"


def write_candidates_markdown(candidates: list[Candidate], path: Path) -> None:
    lines = [
        "# Java Direct SSRF Candidate Screening",
        "",
        "| advisory_path | case_id | project | package | java_direct_ssrf | evidence_strength | repeat_fix_signal | keep_or_drop | reason |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for candidate in candidates:
        lines.append(candidate_row(candidate))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_case_json(candidate: Candidate, repeat_relation: dict[str, Any]) -> dict[str, Any]:
    assert candidate.code_evidence is not None
    repair_pattern = candidate.code_evidence["repair_pattern"]
    ambiguity_rule = candidate.code_evidence["ambiguity_rule"]
    unknown_fields = list(candidate.code_evidence["unknown_fields"])
    if candidate.code_evidence.get("fix_evidence_missing"):
        unknown_fields.append("fix_evidence_missing")
    return {
        "advisory_path": candidate.advisory_path,
        "case_id": candidate.case_id,
        "project": candidate.project,
        "repository": candidate.repository,
        "package": candidate.package,
        "ecosystem": "Java",
        "vuln_type": "direct_ssrf",
        "advisory_urls": candidate.advisory_urls or candidate.reference_urls[:3],
        "fix_commits": candidate.code_evidence["fix_commits"],
        "repair_pattern_inferred_from_commit": repair_pattern,
        "ambiguity_rule_inferred_from_commit": ambiguity_rule,
        "repeat_fix_relation": repeat_relation,
        "payload_family_hints": [],
        "confidence": "high",
        "unknown_fields": sorted(set(unknown_fields)),
    }


def has_complete_code_evidence(code_evidence: dict[str, Any] | None) -> bool:
    if not code_evidence or code_evidence.get("fix_evidence_missing"):
        return False
    evidences = code_evidence.get("repair_pattern", {}).get("evidence", [])
    if not evidences:
        return False
    for evidence in evidences:
        if not evidence.get("commit"):
            return False
        if not evidence.get("file"):
            return False
        if not evidence.get("before_code") or not evidence.get("after_code"):
            return False
        method = evidence.get("method", "")
        if not method or method == "UNKNOWN":
            return False
    return True


def write_trace(candidates: list[Candidate], path: Path) -> None:
    trace = []
    for candidate in candidates:
        trace.append(
            {
                "case_id": candidate.case_id,
                "advisory_path": candidate.advisory_path,
                "advisory_level_evidence": {
                    "aliases": candidate.aliases,
                    "references": candidate.reference_urls,
                    "repository": candidate.repository,
                    "classification": {
                        "java_direct_ssrf": candidate.java_direct_ssrf,
                        "evidence_strength": candidate.evidence_strength,
                        "repeat_fix_signal": candidate.repeat_fix_signal,
                        "keep_or_drop": candidate.keep_or_drop,
                        "reason": candidate.reason,
                    },
                },
                "code_level_evidence": candidate.code_evidence or {"fix_evidence_missing": True},
            }
        )
    path.write_text(json.dumps(trace, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--advisory-root", default=str(ADVISORY_ROOT))
    parser.add_argument("--output-dir", default=str(OUTPUT_DIR))
    args = parser.parse_args()

    advisory_root = Path(args.advisory_root)
    output_dir = Path(args.output_dir)
    if not advisory_root.exists():
        raise SystemExit(f"advisory root not found: {advisory_root}")
    output_dir.mkdir(parents=True, exist_ok=True)

    candidates = find_candidate_advisories(advisory_root)
    with tempfile.TemporaryDirectory(prefix="java-ssrf-repos-") as tmp_dir:
        repo_cache = Path(tmp_dir)
        for candidate in candidates:
            if candidate.keep_or_drop != "keep":
                continue
            try:
                candidate.code_evidence = extract_code_evidence(candidate, repo_cache)
            except (
                subprocess.CalledProcessError,
                subprocess.TimeoutExpired,
                urllib.error.URLError,
                TimeoutError,
                OSError,
            ) as exc:
                candidate.code_evidence = {
                    "fix_evidence_missing": True,
                    "error": str(exc),
                    "unknown_fields": ["fix_evidence_missing"],
                }
            supported = has_complete_code_evidence(candidate.code_evidence)
            candidate.supported_for_code_extraction = supported
            if not supported:
                candidate.keep_or_drop = "drop"
                candidate.reason = "drop: local advisory is Java Direct SSRF, but official code-level fix evidence could not be extracted"

    repeat_relations = build_repeat_relations(candidates)
    kept_cases = [
        build_case_json(candidate, repeat_relations[candidate.case_id])
        for candidate in candidates
        if candidate.keep_or_drop == "keep" and candidate.code_evidence and not candidate.code_evidence.get("fix_evidence_missing")
    ]

    write_candidates_markdown(candidates, output_dir / "java_direct_ssrf_candidates.md")
    (output_dir / "java_direct_ssrf_cases.json").write_text(
        json.dumps(kept_cases, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    write_trace(candidates, output_dir / "java_direct_ssrf_trace.json")

    print(f"candidates={len(candidates)}")
    print(f"retained_cases={len(kept_cases)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
