from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from cvehunt.models import CveRecord


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_cve(cve_id: str, *, timeout: float = 60) -> CveRecord | None:
    params = {"cveId": cve_id.upper()}
    payload = _fetch_payload(params, timeout=timeout)
    vulnerabilities = payload.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list) or not vulnerabilities:
        return None
    return _parse_cve(vulnerabilities[0])


def fetch_recent_cves(days: int = 7, limit: int = 50) -> list[CveRecord]:
    end = datetime.now(UTC)
    start = end - timedelta(days=days)
    params = {
        "pubStartDate": _nvd_date(start),
        "pubEndDate": _nvd_date(end),
        "resultsPerPage": min(limit, 2000),
        "startIndex": 0,
    }
    payload = _fetch_payload(params, timeout=30)
    records = [_parse_cve(item) for item in payload.get("vulnerabilities", [])]
    return records[:limit]


def _fetch_payload(params: dict[str, object], *, timeout: float) -> dict[str, object]:
    request = Request(
        f"{NVD_API}?{urlencode(params)}",
        headers={"User-Agent": "cvehunt-local-eval/0.1"},
    )
    with urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("invalid NVD payload")
    return payload


def _nvd_date(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _parse_cve(item: dict[str, object]) -> CveRecord:
    cve = item.get("cve", {})
    if not isinstance(cve, dict):
        raise ValueError("invalid NVD CVE item")
    cve_id = str(cve.get("id", "UNKNOWN"))
    summary = _english_description(cve)
    metrics = cve.get("metrics", {})
    cvss = _extract_cvss(metrics if isinstance(metrics, dict) else {})
    published = str(cve.get("published", "unknown"))
    references = _extract_references(cve)
    cwes = _extract_cwes(cve)
    ecosystem = _guess_ecosystem(cve)
    vulnerable_versions, patched_versions = _extract_versions(cve, summary)
    return CveRecord(
        cve_id=cve_id,
        name=_derive_name(cve_id, summary, ecosystem),
        summary=summary or "No English description is available from NVD.",
        cvss=cvss,
        disclosed=published[:10] if published != "unknown" else published,
        ecosystem=ecosystem,
        vulnerable_versions=vulnerable_versions,
        patched_versions=patched_versions,
        kev=_is_kev(cve, references),
        known_exploitation_window=_kev_window(cve),
        references=references,
        cwes=cwes,
    )


def _english_description(cve: dict[str, object]) -> str:
    descriptions = cve.get("descriptions", [])
    if not isinstance(descriptions, list):
        return ""
    for description in descriptions:
        if isinstance(description, dict) and description.get("lang") == "en":
            return str(description.get("value", ""))
    return ""


def _extract_cvss(metrics: dict[str, object]) -> float | None:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key)
        if not isinstance(values, list) or not values:
            continue
        first = values[0]
        if not isinstance(first, dict):
            continue
        cvss_data = first.get("cvssData")
        if isinstance(cvss_data, dict) and "baseScore" in cvss_data:
            return float(cvss_data["baseScore"])
    return None


def _extract_references(cve: dict[str, object]) -> list[str]:
    references = cve.get("references", [])
    urls: list[str] = []
    if isinstance(references, dict):
        references = references.get("referenceData", [])
    if isinstance(references, list):
        for reference in references:
            if not isinstance(reference, dict):
                continue
            url = reference.get("url")
            if isinstance(url, str) and url:
                urls.append(url)
    return _dedupe(urls)


def _extract_cwes(cve: dict[str, object]) -> list[str]:
    weaknesses = cve.get("weaknesses", [])
    cwes: list[str] = []
    if not isinstance(weaknesses, list):
        return cwes
    for weakness in weaknesses:
        if not isinstance(weakness, dict):
            continue
        descriptions = weakness.get("description", [])
        if not isinstance(descriptions, list):
            continue
        for description in descriptions:
            if not isinstance(description, dict):
                continue
            value = str(description.get("value", ""))
            if value.startswith("CWE-"):
                cwes.append(value)
    return _dedupe(cwes)


def _guess_ecosystem(cve: dict[str, object]) -> str:
    configurations = cve.get("configurations", [])
    references = cve.get("references", [])
    text = " ".join(
        [
            _english_description(cve),
            json.dumps(configurations),
            json.dumps(references),
        ]
    ).lower()
    if any(token in text for token in ("google:chrome", "google chrome", "chromium", "v8")):
        return "chromium"
    if any(token in text for token in ("linux_kernel", "linux kernel", "kernel.org")):
        return "linux-kernel"
    if "npm" in text or "node" in text or "javascript" in text:
        return "npm"
    if "pypi" in text or "python" in text:
        return "pypi"
    if "maven" in text or "java" in text:
        return "maven"
    if "wordpress" in text:
        return "wordpress"
    return "unknown"


def _derive_name(cve_id: str, summary: str, ecosystem: str) -> str:
    normalized = summary.lower()
    if ecosystem == "chromium" or any(token in normalized for token in ("google chrome", "chromium", "v8")):
        return "Google Chrome / Chromium V8"
    if ecosystem == "linux-kernel":
        return "Linux Kernel"
    if "wordpress" in normalized:
        return "WordPress"
    return "Unknown" if cve_id else "Unknown"


def _extract_versions(cve: dict[str, object], summary: str) -> tuple[list[str], list[str]]:
    vulnerable: list[str] = []
    patched: list[str] = []
    for match in _iter_cpe_matches(cve.get("configurations", [])):
        criteria = str(match.get("criteria") or match.get("cpe23Uri") or "")
        product = _product_from_cpe(criteria)
        if not product:
            continue
        status = str(match.get("vulnerable", True)).lower()
        if status == "false":
            continue
        version_start = _first_string(match, "versionStartIncluding", "versionStartExcluding")
        start_operator = ">=" if match.get("versionStartIncluding") else ">"
        version_end = _first_string(match, "versionEndExcluding", "versionEndIncluding", "lessThan")
        end_operator = "<" if match.get("versionEndExcluding") or match.get("lessThan") else "<="
        cpe_version = _version_from_cpe(criteria)
        if version_start and version_end:
            vulnerable.append(f"{product} {start_operator} {version_start}, {end_operator} {version_end}")
        elif version_end:
            vulnerable.append(f"{product} {end_operator} {version_end}")
        elif cpe_version and cpe_version not in {"*", "-"}:
            vulnerable.append(f"{product} {cpe_version}")
        if version_end and end_operator == "<":
            patched.append(f"{product} {version_end}")

    if not vulnerable:
        prior_to = re.search(r"\bprior to\s+([0-9][0-9A-Za-z_.-]*)", summary, flags=re.IGNORECASE)
        if prior_to:
            product = "google chrome" if "chrome" in summary.lower() else "affected product"
            vulnerable.append(f"{product} < {prior_to.group(1)}")
            patched.append(f"{product} {prior_to.group(1)}")
    return _dedupe(vulnerable), _dedupe(patched)


def _iter_cpe_matches(node: object):
    if isinstance(node, list):
        for entry in node:
            yield from _iter_cpe_matches(entry)
        return
    if not isinstance(node, dict):
        return
    cpe_matches = node.get("cpeMatch", [])
    if isinstance(cpe_matches, list):
        for match in cpe_matches:
            if isinstance(match, dict):
                yield match
    nodes = node.get("nodes", [])
    if isinstance(nodes, list):
        for child in nodes:
            yield from _iter_cpe_matches(child)


def _product_from_cpe(criteria: str) -> str | None:
    parts = criteria.split(":")
    if len(parts) < 5 or not criteria.startswith("cpe:2.3:"):
        return None
    vendor = parts[3].replace("_", " ")
    product = parts[4].replace("_", " ")
    if vendor == "*" or product == "*":
        return None
    return f"{vendor} {product}".strip()


def _version_from_cpe(criteria: str) -> str | None:
    parts = criteria.split(":")
    if len(parts) < 6:
        return None
    return parts[5]


def _first_string(source: dict[str, object], *keys: str) -> str | None:
    for key in keys:
        value = source.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _is_kev(cve: dict[str, object], references: list[str]) -> bool:
    if cve.get("cisaExploitAdd"):
        return True
    return any("known-exploited-vulnerabilities" in reference.lower() for reference in references)


def _kev_window(cve: dict[str, object]) -> str | None:
    added = cve.get("cisaExploitAdd")
    due = cve.get("cisaActionDue")
    if isinstance(added, str) and isinstance(due, str):
        return f"CISA KEV added {added}; due {due}"
    if isinstance(added, str):
        return f"CISA KEV added {added}"
    return None


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped
