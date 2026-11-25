"""Parsing and policy checks for OpenSSH ``authorized_keys`` entries.

The public surface is deliberately small: a single line can be split into an
option set, a key type, a key blob and a trailing comment; a whole file can be
scanned into entries plus per-line errors; a parsed option set can be checked
against a connection context; a key blob can be fingerprinted and matched
against a revocation list.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

KEY_TYPES = frozenset(
    {
        "ssh-rsa",
        "ssh-dss",
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com",
    }
)

_REPEATABLE = ("permitopen", "principals")


def _split_tokens(text: str) -> List[str]:
    """Split a line into whitespace separated pieces."""
    return text.split()


def _split_commas(text: str) -> List[str]:
    """Split an option run into individual options."""
    return text.split(",")


def _unquote(raw: str) -> str:
    """Return the value of a possibly quoted option value."""
    if raw.startswith('"'):
        raw = raw[1:]
        if raw.endswith('"'):
            raw = raw[:-1]
    return raw


def _parse_options(tokens: Sequence[str]) -> Dict[str, Any]:
    options: Dict[str, Any] = {}
    for token in tokens:
        for piece in _split_commas(token):
            piece = piece.strip()
            if not piece:
                continue
            if "=" in piece:
                name, raw = piece.split("=", 1)
                name = name.strip()
                value = _unquote(raw.strip())
            else:
                name = piece
                value = True
            if name == "principals":
                items = [item.strip() for item in value.split(",") if item.strip()]
                options.setdefault("principals", []).extend(items)
            elif name == "permitopen":
                options.setdefault("permitopen", []).append(value)
            else:
                options[name] = value
    return options


def parse_line(line: str) -> Dict[str, Any]:
    """Parse one authorized_keys line into options, type, key blob and comment."""
    text = line.strip()
    if not text or text.startswith("#"):
        raise ValueError("invalid-line")
    tokens = _split_tokens(text)
    index = -1
    for position, token in enumerate(tokens):
        if token in KEY_TYPES:
            index = position
            break
    if index < 0 or index + 1 >= len(tokens):
        raise ValueError("invalid-line")
    key_type = tokens[index]
    comment = ""
    return {
        "options": _parse_options(tokens[:index]),
        "type": key_type,
        "key": " ".join(tokens[index:]),
        "comment": comment,
    }


def parse_file(text: str) -> Dict[str, Any]:
    """Parse a whole authorized_keys file, collecting per-line failures."""
    entries: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    shared: Dict[str, Any] = {}
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            entry = parse_line(line)
        except ValueError as exc:
            errors.append({"line": number, "reason": str(exc)})
            continue
        shared.update(entry["options"])
        entry["options"] = dict(shared)
        entries.append(entry)
    return {"entries": entries, "errors": errors}


def _match_cidr(source: str, spec: str) -> bool:
    try:
        network = ipaddress.ip_network(spec, strict=False)
    except ValueError:
        return False
    try:
        address = ipaddress.ip_address(source)
    except ValueError:
        return False
    if address.version != network.version:
        return False
    width = 32 if address.version == 4 else 128
    host_bits = width - network.prefixlen + 1
    if host_bits >= width:
        return True
    mask = (1 << host_bits) - 1
    return (int(address) | mask) == (int(network.network_address) | mask)


def _match_from(source: Optional[str], spec: str) -> bool:
    if not source:
        return False
    spec = spec.strip()
    if not spec:
        return False
    if "/" in spec:
        return _match_cidr(source, spec)
    if spec.startswith("*."):
        return source.strip().lower().endswith(spec[2:].lower())
    try:
        address = ipaddress.ip_address(source)
    except ValueError:
        return source.strip().lower() == spec.lower()
    try:
        return address == ipaddress.ip_address(spec)
    except ValueError:
        return False


def _match_hostport(source: str, entry: str) -> bool:
    if ":" not in entry or ":" not in source:
        return False
    entry_host, entry_port = entry.rsplit(":", 1)
    source_host, source_port = source.rsplit(":", 1)
    return entry_host.lower() == source_port.lower() and entry_port == source_host


def check_options(options: Mapping[str, Any], ctx: Optional[Mapping[str, Any]] = None) -> List[str]:
    """Return the sorted names of options rejected by the connection context."""
    context: Mapping[str, Any] = ctx or {}
    bad: List[str] = []
    if "from" in options:
        specs = [item.strip() for item in str(options["from"]).split(",") if item.strip()]
        if not any(_match_from(context.get("source"), spec) for spec in specs):
            bad.append("from")
    if "command" in options:
        allowed = context.get("allowed_commands")
        if allowed is not None and options["command"] not in allowed:
            bad.append("command")
    if "permitopen" in options:
        connect = context.get("connect")
        if connect is not None:
            if not any(_match_hostport(connect, entry) for entry in options["permitopen"]):
                bad.append("permitopen")
    if "principals" in options and not context.get("cert"):
        bad.append("principals")
    return sorted(bad)


def fingerprint(blob_b64: str) -> str:
    """Return the OpenSSH style ``SHA256:`` fingerprint of a base64 key blob."""
    raw = base64.b64decode(blob_b64, validate=True)
    digest = hashlib.sha256(raw).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii")


def _normalize_fingerprint(value: str) -> str:
    text = "".join(value.split())
    if text.lower().startswith("sha256:"):
        text = text[7:]
    return text.rstrip("=")


def is_revoked(key_blob: str, revoked_list: Sequence[str]) -> bool:
    """Return whether the key blob matches any fingerprint in the list."""
    target = _normalize_fingerprint(fingerprint(key_blob))
    return target in list(revoked_list)