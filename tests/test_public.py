"""Public smoke tests for authorized_keys parsing and constraint checks."""

from __future__ import annotations

from authkeys import check_options, fingerprint, parse_file, parse_line


def test_parse_line_separates_comment_from_key() -> None:
    entry = parse_line("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKey deploy@bastion")
    assert entry["type"] == "ssh-ed25519"
    assert entry["key"] == "AAAAC3NzaC1lZDI1NTE5AAAAIKey"
    assert entry["comment"] == "deploy@bastion"
    assert entry["options"] == {}


def test_quoted_command_keeps_its_spaces() -> None:
    entry = parse_line('no-pty,command="echo hi" ssh-rsa AAAAB3Nza me')
    assert entry["options"] == {"no-pty": True, "command": "echo hi"}


def test_file_entries_do_not_inherit_options() -> None:
    parsed = parse_file("no-pty ssh-rsa AAAA one\nssh-ed25519 BBBB two\n")
    assert len(parsed["entries"]) == 2
    assert parsed["entries"][1]["options"] == {}


def test_fingerprint_is_unpadded_sha256() -> None:
    value = fingerprint("AAAAC3NzaC1lZDI1NTE5AAAAIKey")
    assert value.startswith("SHA256:")
    assert not value.endswith("=")


def test_pty_denial_is_reported() -> None:
    assert check_options({"no-pty": True}, {"pty": True}) == ["no-pty"]
    assert check_options({"no-pty": True}, {}) == []