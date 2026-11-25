"""Parsing and policy checks for OpenSSH ``authorized_keys`` entries."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
from typing import Any, Dict, List, Mapping, Optional, Sequence

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

# Context field names are not a mechanical hyphen-to-underscore mapping for
# every option, so keep the established aliases explicit.
_NEGATION_CONTEXT_KEYS: Mapping[str, Sequence[str]] = {
    "no-pty": ("pty",),
    "no-port-forwarding": ("forwarding", "port_forwarding"),
    "no-agent-forwarding": ("agent_forwarding",),
    "no-x11-forwarding": ("x11_forwarding",),
    "no-user-rc": ("user_rc",),
}


def _split_tokens(text: str) -> List[str]:
    """Split on unquoted whitespace while keeping quoted runs intact."""
    tokens: List[str] = []
    buffer: List[str] = []
    quoted = False
    escaped = False

    for ch in text:
        if escaped:
            buffer.append(ch)
            escaped = False
        elif ch == "\\" and quoted:
            buffer.append(ch)
            escaped = True
        elif ch == '"':
            quoted = not quoted
            buffer.append(ch)
        elif ch.isspace() and not quoted:
            if buffer:
                tokens.append("".join(buffer))
                buffer = []
        else:
            buffer.append(ch)

    if buffer:
        tokens.append("".join(buffer))
    return tokens


def _split_commas(text: str) -> List[str]:
    """Split on commas that are outside double quotes."""
    parts: List[str] = []
    buffer: List[str] = []
    quoted = False
    escaped = False

    for ch in text:
        if escaped:
            buffer.append(ch)
            escaped = False
        elif ch == "\\" and quoted:
            buffer.append(ch)
            escaped = True
        elif ch == '"':
            quoted = not quoted
            buffer.append(ch)
        elif ch == "," and not quoted:
            parts.append("".join(buffer))
            buffer = []
        else:
            buffer.append(ch)

    parts.append("".join(buffer))
    return parts


def _unquote(raw: str) -> str:
    """Remove surrounding quotes and resolve quoted backslash escapes."""
    if len(raw) >= 2 and raw.startswith('"') and raw.endswith('"'):
        value: List[str] = []
        escaped = False
        for ch in raw[1:-1]:
            if escaped:
                value.append(ch)
                escaped = False
            elif ch == "\\":
                escaped = True
            else:
                value.append(ch)
        return "".join(value)
    return raw


def _parse_options(tokens: Sequence[str]) -> Dict[str, Any]:
    options: Dict[str, Any] = {}

    for token in tokens:
        for piece in _split_commas(token):
            piece = piece.strip()
            if not piece:
                continue

            if "=" in piece:
                name, raw_value = piece.split("=", 1)
                name = name.strip().lower()
                value: Any = _unquote(raw_value.strip())
            else:
                name = piece.strip().lower()
                value = True

            if name == "principals":
                if not isinstance(value, str):
                    raise ValueError("invalid-line")
                items = [item.strip() for item in value.split(",") if item.strip()]
                options.setdefault("principals", []).extend(items)
            elif name == "permitopen":
                if not isinstance(value, str):
                    raise ValueError("invalid-line")
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
    type_index = -1
    for position, token in enumerate(tokens):
        if token in KEY_TYPES:
            type_index = position
            break

    if type_index < 0 or type_index + 1 >= len(tokens):
        raise ValueError("invalid-line")

    return {
        "options": _parse_options(tokens[:type_index]),
        "type": tokens[type_index],
        "key": tokens[type_index + 1],
        "comment": " ".join(tokens[type_index + 2 :]),
    }


def parse_file(text: str) -> Dict[str, Any]:
    """Parse a whole authorized_keys file, collecting per-line failures."""
    entries: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []

    for number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        try:
            entries.append(parse_line(line))
        except ValueError as exc:
            errors.append({"line": number, "reason": str(exc)})

    return {"entries": entries, "errors": errors}


def _match_cidr(source: str, spec: str) -> bool:
    try:
        network = ipaddress.ip_network(spec, strict=False)
        address = ipaddress.ip_address(source)
    except ValueError:
        return False

    if address.version != network.version:
        return False
    return address in network


def _match_from(source: Optional[str], spec: str) -> bool:
    if not source:
        return False

    host = str(source).strip()
    spec = spec.strip()
    if not spec:
        return False

    if "/" in spec:
        return _match_cidr(host, spec)

    if spec.startswith("*."):
        normalized_host = host.lower()
        suffix = spec[1:].lower()  # Includes the separating dot.
        return normalized_host.endswith(suffix) and len(normalized_host) > len(suffix)

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host.lower() == spec.lower()

    try:
        return address == ipaddress.ip_address(spec)
    except ValueError:
        return False


def _match_hostport(source: str, entry: str) -> bool:
    if not isinstance(source, str) or not isinstance(entry, str):
        return False
    if ":" not in entry or ":" not in source:
        return False

    entry_host, entry_port = entry.rsplit(":", 1)
    source_host, source_port = source.rsplit(":", 1)

    if entry_host != "*" and entry_host.lower() != source_host.lower():
        return False
    return entry_port == source_port


def _negation_is_used(name: str, context: Mapping[str, Any]) -> bool:
    context_keys = _NEGATION_CONTEXT_KEYS.get(name)
    if context_keys is None and name.startswith("no-"):
        context_keys = (name[3:].replace("-", "_"),)

    return bool(context_keys and any(context.get(key) for key in context_keys))


def check_options(
    options: Mapping[str, Any], ctx: Optional[Mapping[str, Any]] = None
) -> List[str]:
    """Return the sorted names of options rejected by the connection context."""
    context: Mapping[str, Any] = ctx or {}
    normalized_options = {str(name).lower(): value for name, value in options.items()}
    bad: List[str] = []

    if "from" in normalized_options:
        specs = [
            item.strip()
            for item in str(normalized_options["from"]).split(",")
            if item.strip()
        ]
        if not any(_match_from(context.get("source"), spec) for spec in specs):
            bad.append("from")

    if "command" in normalized_options:
        allowed_commands = context.get("allowed_commands")
        command = normalized_options["command"]
        if allowed_commands is not None and command not in allowed_commands:
            bad.append("command")

    if "permitopen" in normalized_options:
        connect = context.get("connect")
        if connect is not None:
            targets = normalized_options["permitopen"]
            if not any(_match_hostport(connect, target) for target in targets):
                bad.append("permitopen")

    if "principals" in normalized_options and not context.get("cert"):
        bad.append("principals")

    for name, enabled in normalized_options.items():
        if name.startswith("no-") and enabled and _negation_is_used(name, context):
            bad.append(name)

    return sorted(bad)


def fingerprint(blob_b64: str) -> str:
    """Return the OpenSSH style ``SHA256:`` fingerprint of a base64 key blob."""
    cleaned = "".join(blob_b64.split())
    raw = base64.b64decode(cleaned, validate=True)
    digest = hashlib.sha256(raw).digest()
    encoded = base64.b64encode(digest).decode("ascii").rstrip("=")
    return f"SHA256:{encoded}"


def _normalize_fingerprint(value: str) -> str:
    text = "".join(value.split())
    if text.lower().startswith("sha256:"):
        text = text[7:]
    return text.rstrip("=")


def is_revoked(key_blob: str, revoked_list: Sequence[str]) -> bool:
    """Return whether the key blob matches any fingerprint in the list."""
    target = _normalize_fingerprint(fingerprint(key_blob))
    return any(_normalize_fingerprint(item) == target for item in revoked_list)
