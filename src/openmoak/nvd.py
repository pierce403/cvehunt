from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from openmoak.models import CveRecord


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_recent_cves(days: int = 7, limit: int = 50) -> list[CveRecord]:
    end = datetime.now(UTC)
    start = end - timedelta(days=days)
    params = {
        "pubStartDate": _nvd_date(start),
        "pubEndDate": _nvd_date(end),
        "resultsPerPage": min(limit, 2000),
        "startIndex": 0,
    }
    request = Request(
        f"{NVD_API}?{urlencode(params)}",
        headers={"User-Agent": "openmoak-local-eval/0.1"},
    )
    with urlopen(request, timeout=30) as response:
        payload = json.loads(response.read().decode("utf-8"))

    records = [_parse_cve(item) for item in payload.get("vulnerabilities", [])]
    return records[:limit]


def _nvd_date(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _parse_cve(item: dict[str, object]) -> CveRecord:
    cve = item.get("cve", {})
    if not isinstance(cve, dict):
        raise ValueError("invalid NVD CVE item")
    cve_id = str(cve.get("id", "UNKNOWN"))
    descriptions = cve.get("descriptions", [])
    summary = ""
    if isinstance(descriptions, list):
        for description in descriptions:
            if isinstance(description, dict) and description.get("lang") == "en":
                summary = str(description.get("value", ""))
                break
    metrics = cve.get("metrics", {})
    cvss = _extract_cvss(metrics if isinstance(metrics, dict) else {})
    published = str(cve.get("published", "unknown"))
    return CveRecord(
        cve_id=cve_id,
        name="Unknown",
        summary=summary or "No English description is available from NVD.",
        cvss=cvss,
        disclosed=published[:10] if published != "unknown" else published,
        ecosystem=_guess_ecosystem(cve),
        vulnerable_versions=[],
        patched_versions=[],
        kev=False,
    )


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


def _guess_ecosystem(cve: dict[str, object]) -> str:
    configurations = cve.get("configurations", [])
    text = json.dumps(configurations).lower()
    if "npm" in text or "node" in text or "javascript" in text:
        return "npm"
    if "pypi" in text or "python" in text:
        return "pypi"
    if "maven" in text or "java" in text:
        return "maven"
    if "wordpress" in text:
        return "wordpress"
    return "unknown"

