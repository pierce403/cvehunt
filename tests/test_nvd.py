from __future__ import annotations

import json

from cvehunt.nvd import _parse_cve, _parse_cve_services_record, fetch_cve


def test_parse_chromium_v8_nvd_record_extracts_harness_planning_fields() -> None:
    record = _parse_cve(
        {
            "cve": {
                "id": "CVE-2026-11645",
                "published": "2026-06-08T20:16:47.000",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": (
                            "Out of bounds read and write in V8 in Google Chrome prior to "
                            "149.0.7827.103 allowed a remote attacker to execute arbitrary "
                            "code inside a sandbox via a crafted HTML page."
                        ),
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseScore": 8.8}},
                    ]
                },
                "weaknesses": [
                    {"description": [{"lang": "en", "value": "CWE-125"}]},
                    {"description": [{"lang": "en", "value": "CWE-787"}]},
                ],
                "references": [
                    {"url": "https://chromereleases.googleblog.com/example"},
                    {"url": "https://issues.chromium.org/issues/506689381"},
                    {
                        "url": (
                            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                            "?field_cve=CVE-2026-11645"
                        )
                    },
                ],
                "cisaExploitAdd": "2026-06-09",
                "cisaActionDue": "2026-06-23",
                "configurations": [
                    {
                        "nodes": [
                            {
                                "operator": "OR",
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                                        "versionEndExcluding": "149.0.7827.103",
                                    }
                                ],
                            }
                        ]
                    }
                ],
            }
        }
    )

    assert record.name == "Google Chrome / Chromium V8"
    assert record.ecosystem == "chromium"
    assert record.cvss == 8.8
    assert record.disclosed == "2026-06-08"
    assert record.kev is True
    assert record.known_exploitation_window == "CISA KEV added 2026-06-09; due 2026-06-23"
    assert record.vulnerable_versions == ["google chrome < 149.0.7827.103"]
    assert record.patched_versions == ["google chrome 149.0.7827.103"]
    assert record.cwes == ["CWE-125", "CWE-787"]
    assert "https://issues.chromium.org/issues/506689381" in record.references
    assert record.metadata_source == "nvd"


def _chrome_cve_services_payload() -> dict[str, object]:
    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.2",
        "cveMetadata": {
            "cveId": "CVE-2026-11645",
            "state": "PUBLISHED",
            "assignerShortName": "Chrome",
            "datePublished": "2026-06-08T23:27:31.298Z",
            "dateUpdated": "2026-06-10T03:58:04.682Z",
        },
        "containers": {
            "cna": {
                "affected": [
                    {
                        "vendor": "Google",
                        "product": "Chrome",
                        "versions": [
                            {
                                "version": "149.0.7827.103",
                                "status": "affected",
                                "lessThan": "149.0.7827.103",
                                "versionType": "custom",
                            }
                        ],
                    }
                ],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": (
                            "Out of bounds read and write in V8 in Google Chrome prior to "
                            "149.0.7827.103 allowed a remote attacker to execute arbitrary "
                            "code inside a sandbox via a crafted HTML page. "
                            "(Chromium security severity: High)"
                        ),
                    }
                ],
                "problemTypes": [
                    {"descriptions": [{"lang": "en", "description": "Out of bounds memory access"}]}
                ],
                "references": [
                    {
                        "url": (
                            "https://chromereleases.googleblog.com/2026/06/"
                            "stable-channel-update-for-desktop_0153744567.html"
                        )
                    },
                    {"url": "https://issues.chromium.org/issues/506689381"},
                ],
            },
            "adp": [
                {
                    "problemTypes": [
                        {
                            "descriptions": [
                                {
                                    "type": "CWE",
                                    "cweId": "CWE-125",
                                    "lang": "en",
                                    "description": "CWE-125 Out-of-bounds Read",
                                }
                            ]
                        },
                        {
                            "descriptions": [
                                {
                                    "type": "CWE",
                                    "cweId": "CWE-787",
                                    "lang": "en",
                                    "description": "CWE-787 Out-of-bounds Write",
                                }
                            ]
                        },
                    ],
                    "references": [
                        {
                            "url": (
                                "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                                "?field_cve=CVE-2026-11645"
                            )
                        }
                    ],
                    "metrics": [
                        {"cvssV3_1": {"baseScore": 8.8}},
                        {"other": {"type": "kev", "content": {"dateAdded": "2026-06-09"}}},
                    ],
                }
            ],
        },
    }


def test_parse_cve_services_chromium_record_extracts_harness_planning_fields() -> None:
    record = _parse_cve_services_record(_chrome_cve_services_payload())

    assert record.name == "Google Chrome / Chromium V8"
    assert record.ecosystem == "chromium"
    assert record.cvss == 8.8
    assert record.disclosed == "2026-06-08"
    assert record.kev is True
    assert record.known_exploitation_window == "CISA KEV added 2026-06-09"
    assert record.vulnerable_versions == ["google chrome < 149.0.7827.103"]
    assert record.patched_versions == ["google chrome 149.0.7827.103"]
    assert record.cwes == ["CWE-125", "CWE-787"]
    assert "https://issues.chromium.org/issues/506689381" in record.references
    assert record.metadata_source == "cve_services"


def test_fetch_cve_falls_back_to_cve_services_when_nvd_lags(monkeypatch) -> None:
    calls: list[str] = []

    class FakeResponse:
        def __init__(self, payload: dict[str, object]) -> None:
            self.payload = payload

        def __enter__(self) -> "FakeResponse":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            return json.dumps(self.payload).encode("utf-8")

    def fake_urlopen(request, timeout: float):
        url = request.full_url
        calls.append(url)
        if "services.nvd.nist.gov" in url:
            return FakeResponse({"vulnerabilities": []})
        return FakeResponse(_chrome_cve_services_payload())

    monkeypatch.setattr("cvehunt.nvd.urlopen", fake_urlopen)

    record = fetch_cve("CVE-2026-11645", timeout=0.1)

    assert record is not None
    assert record.ecosystem == "chromium"
    assert record.metadata_source == "cve_services"
    assert any("services.nvd.nist.gov" in url for url in calls)
    assert any("cveawg.mitre.org" in url for url in calls)
