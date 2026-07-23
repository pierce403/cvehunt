import json
from pathlib import Path

from cvehunt.provenance import (
    ATTESTATION,
    DERIVATION,
    parse_exploit_provenance,
    validate_exploit_provenance,
)


def valid_declaration() -> dict:
    return {
        "schema_version": 1,
        "derivation": DERIVATION,
        "external_poc_code_used": False,
        "external_poc_sources_consulted": [],
        "research_sources": [
            {
                "category": "affected_fixed_diff",
                "reference": "vendor tags v1.2.3..v1.2.4",
                "used_for": "identify the changed parser invariant",
            },
            {
                "category": "general_technique",
                "reference": "well-established deserialization gadget construction",
                "used_for": "independently implement the target-specific chain",
            },
        ],
        "techniques_or_gadgets": ["deserialization gadget chain"],
        "attestation": ATTESTATION,
    }


def tagged(data: dict) -> str:
    return (
        '<CVEHUNT_FILE path="exploit_provenance.json">\n'
        + json.dumps(data)
        + "\n</CVEHUNT_FILE>"
    )


def test_valid_from_scratch_declaration() -> None:
    declaration = valid_declaration()
    assert validate_exploit_provenance(declaration) == []
    result = parse_exploit_provenance(tagged(declaration))
    assert result["status"] == "valid"
    assert result["valid"] is True
    assert result["declaration"] == declaration


def test_external_poc_use_is_rejected() -> None:
    declaration = valid_declaration()
    declaration["external_poc_code_used"] = True
    declaration["external_poc_sources_consulted"] = ["https://example.test/exploit.py"]
    result = parse_exploit_provenance(tagged(declaration))
    assert result["status"] == "invalid"
    assert result["valid"] is False
    assert any("external_poc_code_used" in error for error in result["errors"])
    assert any("external_poc_sources_consulted" in error for error in result["errors"])


def test_exploit_source_category_is_not_allowed() -> None:
    declaration = valid_declaration()
    declaration["research_sources"][0]["category"] = "external_poc"
    errors = validate_exploit_provenance(declaration)
    assert any("category is not allowed" in error for error in errors)


def test_missing_and_duplicate_declarations_are_rejected() -> None:
    assert parse_exploit_provenance("no artifact")["status"] == "missing"
    declaration = tagged(valid_declaration())
    duplicate = parse_exploit_provenance(declaration + "\n" + declaration)
    assert duplicate["status"] == "invalid"
    assert any("multiple" in error for error in duplicate["errors"])


def test_fenced_json_declaration_is_accepted() -> None:
    body = json.dumps(valid_declaration(), indent=2)
    response = (
        '<CVEHUNT_FILE path="exploit_provenance.json">\n```json\n'
        + body
        + '\n```\n</CVEHUNT_FILE>'
    )
    assert parse_exploit_provenance(response)["valid"] is True


def test_contributor_prompt_forbids_external_poc_reuse_and_requires_attestation() -> None:
    script = (Path(__file__).parents[1] / "contribute.sh").read_text(encoding="utf-8")
    assert "A finished public exploit is an answer key" in script
    assert "Do not clone, download, inspect, or execute external PoC/exploit repositories" in script
    assert "exploit_provenance.json" in script
    assert ATTESTATION in script
    assert 'model exploit artifact requires valid from-scratch provenance' in script
