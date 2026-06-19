from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from cvehunt.models import CveRecord


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_SERVICES_API = "https://cveawg.mitre.org/api/cve"


def fetch_cve(cve_id: str, *, timeout: float = 60) -> CveRecord | None:
    params = {"cveId": cve_id.upper()}
    try:
        payload = _fetch_payload(params, timeout=timeout)
        vulnerabilities = payload.get("vulnerabilities", [])
        if isinstance(vulnerabilities, list) and vulnerabilities:
            return _parse_cve(vulnerabilities[0])
    except Exception:
        pass
    try:
        return _fetch_cve_services_record(cve_id, timeout=timeout)
    except Exception:
        return None


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


def _fetch_cve_services_record(cve_id: str, *, timeout: float) -> CveRecord | None:
    request = Request(
        f"{CVE_SERVICES_API}/{quote(cve_id.upper())}",
        headers={"User-Agent": "cvehunt-local-eval/0.1"},
    )
    with urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("invalid CVE Services payload")
    state = _nested_str(payload, ["cveMetadata", "state"]).upper()
    if state and state != "PUBLISHED":
        return None
    return _parse_cve_services_record(payload)


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
        metadata_source="nvd",
    )


def _parse_cve_services_record(payload: dict[str, object]) -> CveRecord:
    metadata = payload.get("cveMetadata", {})
    containers = payload.get("containers", {})
    if not isinstance(metadata, dict) or not isinstance(containers, dict):
        raise ValueError("invalid CVE Services record")
    cna = containers.get("cna", {})
    if not isinstance(cna, dict):
        raise ValueError("invalid CVE Services CNA container")
    cve_id = str(metadata.get("cveId", "UNKNOWN"))
    summary = _cve_services_english_description(cna)
    references = _extract_cve_services_references(containers)
    cwes = _extract_cve_services_cwes(containers)
    ecosystem = _guess_ecosystem_from_text(
        " ".join(
            [
                summary,
                json.dumps(cna.get("affected", [])),
                json.dumps(cna.get("problemTypes", [])),
                " ".join(references),
                " ".join(cwes),
            ]
        )
    )
    vulnerable_versions, patched_versions = _extract_cve_services_versions(cna)
    return CveRecord(
        cve_id=cve_id,
        name=_derive_name(cve_id, summary, ecosystem),
        summary=summary or "No English description is available from CVE Services.",
        cvss=_extract_cve_services_cvss(containers),
        disclosed=_first_date_prefix(
            metadata,
            "datePublished",
            "dateUpdated",
            "dateReserved",
        ),
        ecosystem=ecosystem,
        vulnerable_versions=vulnerable_versions,
        patched_versions=patched_versions,
        kev=_cve_services_is_kev(containers, references),
        known_exploitation_window=_cve_services_kev_window(containers),
        references=references,
        cwes=cwes,
        metadata_source="cve_services",
    )


def _cve_services_english_description(container: dict[str, object]) -> str:
    descriptions = container.get("descriptions", [])
    if not isinstance(descriptions, list):
        return ""
    for description in descriptions:
        if isinstance(description, dict) and description.get("lang") == "en":
            return str(description.get("value", ""))
    return ""


def _extract_cve_services_references(containers: dict[str, object]) -> list[str]:
    urls: list[str] = []
    for container in _iter_cve_services_containers(containers):
        references = container.get("references", [])
        if not isinstance(references, list):
            continue
        for reference in references:
            if not isinstance(reference, dict):
                continue
            url = reference.get("url")
            if isinstance(url, str) and url:
                urls.append(url)
    return _dedupe(urls)


def _extract_cve_services_cwes(containers: dict[str, object]) -> list[str]:
    cwes: list[str] = []
    for container in _iter_cve_services_containers(containers):
        problem_types = container.get("problemTypes", [])
        if not isinstance(problem_types, list):
            continue
        for problem_type in problem_types:
            if not isinstance(problem_type, dict):
                continue
            descriptions = problem_type.get("descriptions", [])
            if not isinstance(descriptions, list):
                continue
            for description in descriptions:
                if not isinstance(description, dict):
                    continue
                cwe_id = description.get("cweId")
                if isinstance(cwe_id, str) and cwe_id.startswith("CWE-"):
                    cwes.append(cwe_id)
                    continue
                value = str(description.get("description") or description.get("value") or "")
                match = re.search(r"\bCWE-\d+\b", value)
                if match:
                    cwes.append(match.group(0))
    return _dedupe(cwes)


def _extract_cve_services_cvss(containers: dict[str, object]) -> float | None:
    for container in _iter_cve_services_containers(containers):
        metrics = container.get("metrics", [])
        if not isinstance(metrics, list):
            continue
        for metric in metrics:
            if not isinstance(metric, dict):
                continue
            for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
                data = metric.get(key)
                if isinstance(data, dict) and "baseScore" in data:
                    return float(data["baseScore"])
    return None


def _extract_cve_services_versions(cna: dict[str, object]) -> tuple[list[str], list[str]]:
    vulnerable: list[str] = []
    patched: list[str] = []
    affected = cna.get("affected", [])
    if not isinstance(affected, list):
        return vulnerable, patched
    for item in affected:
        if not isinstance(item, dict):
            continue
        product = _affected_product_name(item)
        if not product:
            continue
        versions = item.get("versions", [])
        if not isinstance(versions, list):
            continue
        for version in versions:
            if not isinstance(version, dict):
                continue
            status = str(version.get("status", "")).lower()
            less_than = _first_string(version, "lessThan", "lessThanOrEqual")
            boundary_operator = "<=" if version.get("lessThanOrEqual") else "<"
            version_value = _first_string(version, "version")
            if status == "affected":
                if less_than:
                    vulnerable.append(f"{product} {boundary_operator} {less_than}")
                    if boundary_operator == "<":
                        patched.append(f"{product} {less_than}")
                elif version_value and version_value not in {"*", "-"}:
                    vulnerable.append(f"{product} {version_value}")
            elif status in {"unaffected", "fixed"} and version_value and version_value not in {"*", "-"}:
                patched.append(f"{product} {version_value}")
        default_status = str(item.get("defaultStatus", "")).lower()
        if default_status in {"unaffected", "fixed"} and not patched:
            versions = [v for v in versions if isinstance(v, dict)]
            for version in versions:
                less_than = _first_string(version, "lessThan")
                if less_than:
                    patched.append(f"{product} {less_than}")
                    break
    return _dedupe(vulnerable), _dedupe(patched)


def _affected_product_name(item: dict[str, object]) -> str | None:
    vendor = str(item.get("vendor") or "").replace("_", " ").strip()
    product = str(item.get("product") or "").replace("_", " ").strip()
    if not product or product in {"*", "-"}:
        return None
    if vendor and vendor not in {"*", "-"}:
        return f"{vendor} {product}".strip().lower()
    return product.lower()


def _iter_cve_services_containers(containers: dict[str, object]):
    cna = containers.get("cna")
    if isinstance(cna, dict):
        yield cna
    adp = containers.get("adp", [])
    if isinstance(adp, list):
        for container in adp:
            if isinstance(container, dict):
                yield container


def _cve_services_is_kev(containers: dict[str, object], references: list[str]) -> bool:
    if any("known-exploited-vulnerabilities" in reference.lower() for reference in references):
        return True
    for container in _iter_cve_services_containers(containers):
        metrics = container.get("metrics", [])
        if not isinstance(metrics, list):
            continue
        for metric in metrics:
            if not isinstance(metric, dict):
                continue
            other = metric.get("other")
            if not isinstance(other, dict):
                continue
            if str(other.get("type", "")).lower() == "kev":
                return True
    return False


def _cve_services_kev_window(containers: dict[str, object]) -> str | None:
    for container in _iter_cve_services_containers(containers):
        metrics = container.get("metrics", [])
        if not isinstance(metrics, list):
            continue
        for metric in metrics:
            if not isinstance(metric, dict):
                continue
            other = metric.get("other")
            if not isinstance(other, dict):
                continue
            if str(other.get("type", "")).lower() != "kev":
                continue
            content = other.get("content", {})
            if isinstance(content, dict):
                date_added = content.get("dateAdded")
                if isinstance(date_added, str) and date_added:
                    return f"CISA KEV added {date_added}"
    return None


def _first_date_prefix(source: dict[str, object], *keys: str) -> str:
    for key in keys:
        value = source.get(key)
        if isinstance(value, str) and value:
            return value[:10]
    return "unknown"


def _nested_str(source: dict[str, object], keys: list[str]) -> str:
    current: object = source
    for key in keys:
        if not isinstance(current, dict):
            return ""
        current = current.get(key)
    return current if isinstance(current, str) else ""


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
    )
    return _guess_ecosystem_from_text(text)


def _guess_ecosystem_from_text(text: str) -> str:
    text = text.lower()
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
