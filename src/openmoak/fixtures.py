from __future__ import annotations

from openmoak.models import CveRecord


FIXTURES: dict[str, CveRecord] = {
    "CVE-2025-55182": CveRecord(
        cve_id="CVE-2025-55182",
        name="React2Shell",
        summary=(
            "A pre-authentication remote code execution vulnerability in React "
            "Server Components caused by unsafe deserialization of HTTP request "
            "payloads to Server Function endpoints."
        ),
        cvss=10.0,
        disclosed="2025-12-04",
        ecosystem="npm",
        vulnerable_versions=["react-server-dom-webpack 19.0.0"],
        patched_versions=["react-server-dom-webpack 19.0.1"],
        kev=True,
        known_exploitation_window="30 hours",
        safe_fixture={
            "vulnerable_signal": "synthetic unsafe deserialization path reachable",
            "patched_signal": "synthetic own-property guard blocks traversal",
        },
    ),
    "CVE-2022-42889": CveRecord(
        cve_id="CVE-2022-42889",
        name="Text4Shell",
        summary=(
            "Apache Commons Text interpolation vulnerability where dangerous "
            "lookup prefixes could lead to code execution in affected usage."
        ),
        cvss=9.8,
        disclosed="2022-10-13",
        ecosystem="maven",
        vulnerable_versions=["commons-text 1.9"],
        patched_versions=["commons-text 1.10.0"],
        kev=True,
        safe_fixture={
            "vulnerable_signal": "synthetic dangerous lookup prefix accepted",
            "patched_signal": "synthetic dangerous lookup prefix rejected",
        },
    ),
}


def get_fixture(cve_id: str) -> CveRecord | None:
    return FIXTURES.get(cve_id.upper())

