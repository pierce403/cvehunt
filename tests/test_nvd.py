from __future__ import annotations

from cvehunt.nvd import _parse_cve


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
