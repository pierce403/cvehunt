from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
POC = (
    ROOT
    / "cves"
    / "CVE-2026-63030"
    / "runs"
    / "2026-07-19T03-53-05Z"
    / "exploiter"
    / "full-chain-poc.py"
)


def _load_poc():
    spec = importlib.util.spec_from_file_location("cvehunt_full_chain_poc", POC)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _args(module, url: str, command: str = "printf CVEHUNT_WP2SHELL_RCE_OK"):
    return module.build_parser().parse_args(["shell", url, "--cmd", command])


def test_full_chain_poc_accepts_only_the_fixed_loopback_pair() -> None:
    poc = _load_poc()
    poc._enforce_cvehunt_lab_policy(_args(poc, "http://127.0.0.1:4080"))
    poc._enforce_cvehunt_lab_policy(_args(poc, "http://127.0.0.1:4081/"))

    for url in (
        "http://localhost:4080",
        "http://127.0.0.1:8080",
        "https://127.0.0.1:4080",
        "http://example.com",
        "http://127.0.0.1:4080/wordpress",
        "http://127.0.0.1:4080?next=http://example.com",
    ):
        with pytest.raises(ValueError, match="refusing non-lab target"):
            poc._enforce_cvehunt_lab_policy(_args(poc, url))


def test_full_chain_poc_rejects_arbitrary_commands_and_other_modes() -> None:
    poc = _load_poc()
    with pytest.raises(ValueError, match="refusing arbitrary command"):
        poc._enforce_cvehunt_lab_policy(_args(poc, "http://127.0.0.1:4080", "id"))

    check_args = poc.build_parser().parse_args(["check", "http://127.0.0.1:4080"])
    with pytest.raises(ValueError, match="only the full shell chain"):
        poc._enforce_cvehunt_lab_policy(check_args)


def test_full_chain_poc_ignores_environment_proxy_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    poc = _load_poc()
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.invalid:9999")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:9999")
    def fail_if_environment_proxies_are_loaded():
        raise AssertionError("environment proxy lookup must not occur")

    monkeypatch.setattr(poc.urllib.request, "getproxies", fail_if_environment_proxies_are_loaded)
    poc.HttpConfig().opener()


def test_full_chain_poc_emits_machine_readable_primitive_blocked_stage(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    poc = _load_poc()

    class BlockedCreator:
        def __init__(self, *args, **kwargs):
            pass

        def create_admin(self):
            raise RuntimeError("UNION fake-post primitive not available (patched, or object cache on)")

    monkeypatch.setattr(poc, "PreAuthAdminCreator", BlockedCreator)
    assert poc.cmd_shell(_args(poc, "http://127.0.0.1:4081")) == 1
    assert '[CVEHUNT_RESULT] {"stage":"primitive_blocked","success":false}' in capsys.readouterr().out


def test_full_chain_poc_rejects_interactive_and_transport_overrides() -> None:
    poc = _load_poc()
    for extra, message in (
        (["--interactive"], "interactive mode"),
        (["--user", "admin", "--password", "secret"], "supplied credentials"),
        (["--proxy", "http://127.0.0.1:9999"], "proxy"),
        (["--insecure"], "insecure TLS"),
        (["--header", "X-Test: value"], "custom headers"),
    ):
        args = poc.build_parser().parse_args(
            ["shell", "http://127.0.0.1:4080", "--cmd", "printf CVEHUNT_WP2SHELL_RCE_OK", *extra]
        )
        with pytest.raises(ValueError, match=message):
            poc._enforce_cvehunt_lab_policy(args)
