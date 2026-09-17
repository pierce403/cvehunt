from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from cvehunt.benchmark_adapters import (
    CANARY_OBSERVATION_SCHEMA,
    CVE55182CapabilityOracle,
    CVE55182TargetIdentityValidator,
    CVE63030CapabilityOracle,
    CVE63030TargetIdentityValidator,
    CVE_63030,
    CVE_55182,
    REACT_TARGET_ACQUISITION_SCHEMA,
    REACT_TARGET_BINDING_SCHEMA,
    REACT_TARGET_POLICY_SCHEMA,
    REACT_TARGET_POLICY_SCHEMA_V2,
    TARGET_ACQUISITION_SCHEMA,
    TARGET_BINDING_SCHEMA,
    TARGET_POLICY_SCHEMA,
)
from cvehunt.pipeline_runtime import (
    CapabilityOracleArmRequest,
    CapabilityOracleRequest,
    RuntimeValidationError,
)
from cvehunt.stage_contracts import canonical_json, sha256_bytes

VULNERABLE_IMAGE = "wordpress:6.9.4-php8.3-apache@sha256:" + "1" * 64
PATCHED_IMAGE = "wordpress:6.9.5-php8.3-apache@sha256:" + "2" * 64
NODE_IMAGE = "node:22-alpine@sha256:" + "5" * 64


def fixture(tmp_path: Path):
    sources = {"source-v": b"official vulnerable release", "source-p": b"official patched release"}
    variants = [
        {
            "name": "vulnerable", "version": "6.9.4",
            "source_uri": "https://wordpress.org/wordpress-6.9.4.tar.gz",
            "source_sha256": hashlib.sha256(sources["source-v"]).hexdigest(),
            "base_image": VULNERABLE_IMAGE,
        },
        {
            "name": "patched", "version": "6.9.5",
            "source_uri": "https://wordpress.org/wordpress-6.9.5.tar.gz",
            "source_sha256": hashlib.sha256(sources["source-p"]).hexdigest(),
            "base_image": PATCHED_IMAGE,
        },
    ]
    policy = {
        "schema": TARGET_POLICY_SCHEMA, "cve_id": CVE_63030, "variants": variants,
    }
    policy_path = tmp_path / "policy.json"
    policy_path.write_bytes(canonical_json(policy))
    policy_path.chmod(0o600)
    manifest_variants = []
    for item, artifact_id in zip(variants, ("source-v", "source-p"), strict=True):
        manifest_variants.append({**item, "source_artifact_id": artifact_id})
    manifest = canonical_json({
        "schema": TARGET_ACQUISITION_SCHEMA,
        "cve_id": CVE_63030,
        "variants": manifest_variants,
    })
    artifacts = {
        **sources,
        "manifest": manifest,
        "docker-v": f"FROM {VULNERABLE_IMAGE}\n".encode(),
        "docker-p": f"FROM {PATCHED_IMAGE}\n".encode(),
    }
    harness_payload = {
        "safety": {
            "trusted_target_identity": {
                "schema": TARGET_BINDING_SCHEMA,
                "manifest_artifact_id": "manifest",
                "dockerfile_artifact_ids": {
                    "vulnerable": "docker-v", "patched": "docker-p",
                },
            },
        },
    }
    return policy_path, harness_payload, artifacts


def test_pinned_official_target_pair_produces_distinct_identity_commitments(tmp_path: Path) -> None:
    policy_path, harness_payload, artifacts = fixture(tmp_path)
    validator = CVE63030TargetIdentityValidator(
        policy_path, expected_uid=os.getuid(),
    )

    identities = validator.validate(
        cve_id=CVE_63030, harness_payload=harness_payload, artifacts=artifacts,
    )

    assert set(identities) == {"vulnerable", "patched"}
    assert identities["vulnerable"] != identities["patched"]
    assert all(len(value) == 64 for value in identities.values())


@pytest.mark.parametrize("mutation", ["source", "dockerfile", "uri", "variant"])
def test_target_provenance_mismatch_fails_closed(tmp_path: Path, mutation: str) -> None:
    policy_path, harness_payload, artifacts = fixture(tmp_path)
    validator = CVE63030TargetIdentityValidator(policy_path, expected_uid=os.getuid())
    changed = dict(artifacts)
    if mutation == "source":
        changed["source-v"] = b"untrusted replacement"
    elif mutation == "dockerfile":
        changed["docker-v"] += b"COPY backdoor.php /var/www/html/\n"
    else:
        manifest = json.loads(changed["manifest"])
        if mutation == "uri":
            manifest["variants"][0]["source_uri"] = "https://example.invalid/wordpress.tar.gz"
        else:
            manifest["variants"][0]["version"] = "6.9.3"
        changed["manifest"] = canonical_json(manifest)

    with pytest.raises(RuntimeValidationError):
        validator.validate(
            cve_id=CVE_63030, harness_payload=harness_payload, artifacts=changed,
        )


def test_nonce_canary_oracle_ignores_candidate_success_claims() -> None:
    nonce = b"n" * 32
    arm = CapabilityOracleArmRequest(
        CVE_63030, nonce, "vulnerable", "1" * 64, "2" * 64,
    )
    oracle = CVE63030CapabilityOracle()
    oracle.arm(arm)
    absent = canonical_json({
        "schema": CANARY_OBSERVATION_SCHEMA,
        "present": False,
        "content_sha256": sha256_bytes(b""),
        "content_bytes": 0,
    })
    request = CapabilityOracleRequest(
        CVE_63030, nonce, "vulnerable", "1" * 64, "2" * 64, "3" * 64,
        b'{"triggered":true,"evidence":"self report"}', b"", absent,
    )

    observation = oracle.observe(request)

    assert observation.capability_proved is False
    assert b"self report" not in observation.observed_interaction


def test_nonce_canary_oracle_accepts_exact_target_side_effect_and_binds_receipt() -> None:
    nonce = b"z" * 32
    oracle = CVE63030CapabilityOracle()
    oracle.arm(CapabilityOracleArmRequest(
        CVE_63030, nonce, "vulnerable", "1" * 64, "2" * 64,
    ))
    expected = nonce.hex().encode()
    host = canonical_json({
        "schema": CANARY_OBSERVATION_SCHEMA,
        "present": True,
        "content_sha256": sha256_bytes(expected),
        "content_bytes": len(expected),
    })

    observation = oracle.observe(CapabilityOracleRequest(
        CVE_63030, nonce, "vulnerable", "1" * 64, "2" * 64, "3" * 64,
        b'{"triggered":false,"evidence":"candidate denied success"}', b"", host,
    ))

    assert observation.capability_proved is True
    interaction = json.loads(observation.observed_interaction)
    assert interaction["candidate_commitment"] == "2" * 64
    assert interaction["target_digest"] == "1" * 64
    assert interaction["capability_proved"] is True


def react_fixture(tmp_path: Path):
    sources = {"react-source-v": b"official npm vulnerable", "react-source-p": b"official npm patched"}
    variants = []
    manifest_variants = []
    for name, version, artifact_id, destination in (
        ("vulnerable", "19.0.0", "react-source-v", "packages/vulnerable"),
        ("patched", "19.0.1", "react-source-p", "packages/patched"),
    ):
        record = {
            "name": name,
            "version": version,
            "source_uri": (
                "https://registry.npmjs.org/react-server-dom-webpack/-/"
                f"react-server-dom-webpack-{version}.tgz"
            ),
            "source_sha256": hashlib.sha256(sources[artifact_id]).hexdigest(),
            "base_image": NODE_IMAGE,
        }
        variants.append(record)
        manifest_variants.append({
            **record, "source_artifact_id": artifact_id,
            "archive_destination": destination,
        })
    policy_path = tmp_path / "react-policy.json"
    policy_path.write_bytes(canonical_json({
        "schema": REACT_TARGET_POLICY_SCHEMA,
        "cve_id": CVE_55182,
        "package": "react-server-dom-webpack",
        "variants": variants,
    }))
    policy_path.chmod(0o600)
    artifacts = {
        **sources,
        "react-manifest": canonical_json({
            "schema": REACT_TARGET_ACQUISITION_SCHEMA,
            "cve_id": CVE_55182,
            "package": "react-server-dom-webpack",
            "variants": manifest_variants,
        }),
        "react-docker-v": (
            f"FROM {NODE_IMAGE}\nCOPY packages/vulnerable/ /app/node_modules/react-server-dom-webpack/\n"
        ).encode(),
        "react-docker-p": (
            f"FROM {NODE_IMAGE}\nCOPY packages/patched/ /app/node_modules/react-server-dom-webpack/\n"
        ).encode(),
    }
    harness = {
        "safety": {"trusted_target_identity": {
            "schema": REACT_TARGET_BINDING_SCHEMA,
            "manifest_artifact_id": "react-manifest",
            "dockerfile_artifact_ids": {
                "vulnerable": "react-docker-v", "patched": "react-docker-p",
            },
        }},
        "container_plan": {
            "schema": "cvehunt.container-plan/v2",
            "archives": [
                {"artifact_id": "react-source-v", "destination": "packages/vulnerable", "format": "tar_gz", "strip_components": 1},
                {"artifact_id": "react-source-p", "destination": "packages/patched", "format": "tar_gz", "strip_components": 1},
            ],
        },
    }
    return policy_path, harness, artifacts


def test_react2shell_target_pair_binds_official_npm_archives_to_controls(tmp_path: Path) -> None:
    policy, harness, artifacts = react_fixture(tmp_path)
    validator = CVE55182TargetIdentityValidator(policy, expected_uid=os.getuid())

    identities = validator.validate(
        cve_id=CVE_55182, harness_payload=harness, artifacts=artifacts,
    )

    assert set(identities) == {"vulnerable", "patched"}
    assert identities["vulnerable"] != identities["patched"]


def test_react2shell_target_policy_accepts_any_complete_approved_pair(tmp_path: Path) -> None:
    policy, harness, artifacts = react_fixture(tmp_path)
    manifest = json.loads(artifacts["react-manifest"])
    selected = {
        item["name"]: {
            key: item[key]
            for key in ("name", "version", "source_uri", "source_sha256", "base_image")
        }
        for item in manifest["variants"]
    }
    other = {
        "vulnerable": {
            **selected["vulnerable"], "version": "19.2.0",
            "source_uri": "https://registry.npmjs.org/react-server-dom-webpack/-/react-server-dom-webpack-19.2.0.tgz",
            "source_sha256": "a" * 64,
        },
        "patched": {
            **selected["patched"], "version": "19.2.1",
            "source_uri": "https://registry.npmjs.org/react-server-dom-webpack/-/react-server-dom-webpack-19.2.1.tgz",
            "source_sha256": "b" * 64,
        },
    }
    policy.write_bytes(canonical_json({
        "schema": REACT_TARGET_POLICY_SCHEMA_V2,
        "cve_id": CVE_55182,
        "package": "react-server-dom-webpack",
        "variant_pairs": [other, selected],
    }))

    identities = CVE55182TargetIdentityValidator(policy, expected_uid=os.getuid()).validate(
        cve_id=CVE_55182, harness_payload=harness, artifacts=artifacts,
    )

    assert set(identities) == {"vulnerable", "patched"}


def test_react2shell_target_policy_rejects_cross_pair_selection(tmp_path: Path) -> None:
    policy, harness, artifacts = react_fixture(tmp_path)
    value = json.loads(policy.read_text())
    first = {item["name"]: item for item in value["variants"]}
    second = {
        "vulnerable": {
            **first["vulnerable"], "version": "19.2.0",
            "source_uri": "https://registry.npmjs.org/react-server-dom-webpack/-/react-server-dom-webpack-19.2.0.tgz",
        },
        "patched": {
            **first["patched"], "version": "19.2.1",
            "source_uri": "https://registry.npmjs.org/react-server-dom-webpack/-/react-server-dom-webpack-19.2.1.tgz",
        },
    }
    policy.write_bytes(canonical_json({
        "schema": REACT_TARGET_POLICY_SCHEMA_V2,
        "cve_id": CVE_55182,
        "package": "react-server-dom-webpack",
        "variant_pairs": [first, second],
    }))
    manifest = json.loads(artifacts["react-manifest"])
    patched = next(item for item in manifest["variants"] if item["name"] == "patched")
    patched.update({
        "version": "19.2.1",
        "source_uri": "https://registry.npmjs.org/react-server-dom-webpack/-/react-server-dom-webpack-19.2.1.tgz",
    })
    artifacts["react-manifest"] = canonical_json(manifest)

    with pytest.raises(RuntimeValidationError, match="target pair does not match pinned policy"):
        CVE55182TargetIdentityValidator(policy, expected_uid=os.getuid()).validate(
            cve_id=CVE_55182, harness_payload=harness, artifacts=artifacts,
        )


@pytest.mark.parametrize("cross_wire", ["patched", "parent", "wildcard"])
def test_react2shell_target_rejects_cross_wired_dockerfile(tmp_path: Path, cross_wire: str) -> None:
    policy, harness, artifacts = react_fixture(tmp_path)
    if cross_wire == "patched":
        artifacts["react-docker-v"] = artifacts["react-docker-p"]
    else:
        source = "packages/" if cross_wire == "parent" else "packages/*"
        artifacts["react-docker-v"] += f"COPY {source} /tmp/cross-wired/\n".encode()

    with pytest.raises(RuntimeValidationError, match="selected official package"):
        CVE55182TargetIdentityValidator(policy, expected_uid=os.getuid()).validate(
            cve_id=CVE_55182, harness_payload=harness, artifacts=artifacts,
        )


def test_react2shell_oracle_accepts_only_exact_nonce_effect() -> None:
    nonce = b"r" * 32
    oracle = CVE55182CapabilityOracle()
    oracle.arm(CapabilityOracleArmRequest(
        CVE_55182, nonce, "vulnerable", "1" * 64, "2" * 64,
    ))
    expected = nonce.hex().encode()
    observed = oracle.observe(CapabilityOracleRequest(
        CVE_55182, nonce, "vulnerable", "1" * 64, "2" * 64, "3" * 64,
        b'{"triggered":false,"evidence":"ignored"}', b"", canonical_json({
            "schema": CANARY_OBSERVATION_SCHEMA,
            "present": True,
            "content_sha256": sha256_bytes(expected),
            "content_bytes": len(expected),
        }),
    ))

    assert observed.capability_proved is True
