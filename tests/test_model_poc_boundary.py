from pathlib import Path

from cvehunt.agents import localhost_only_poc_command


def test_model_poc_command_enforces_loopback_only_systemd_boundary(tmp_path: Path) -> None:
    command = localhost_only_poc_command(tmp_path, 30)

    assert command[:3] == ["sudo", "-n", "systemd-run"]
    assert "IPAddressDeny=any" in command
    assert "IPAddressAllow=localhost" in command
    assert "RuntimeMaxSec=35" in command
    assert f"WorkingDirectory={tmp_path.resolve()}" in command
    assert command[-2:] == ["/usr/bin/python3", "model_attempt/poc.py"]
