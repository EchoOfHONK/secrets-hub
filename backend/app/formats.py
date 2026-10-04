"""Local parsers and formatters. Secret material never leaves the application."""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import ipaddress
import json
import re
from typing import Any

import qrcode
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from dotenv import dotenv_values

MAX_IMPORT_BYTES = 8 * 1024 * 1024
MAX_IMPORT_RECORDS = 500
KINDS = {"login", "api_key", "token", "ssh_key", "wireguard", "environment", "certificate", "note", "file"}


def qr_data_url(value: str) -> str:
    if len(value.encode()) > 2950:
        raise ValueError("Configuration is too large for a QR code; download the file instead")
    image = qrcode.make(value, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=6, border=4)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode("ascii")


def _wg_key(value: str) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("WireGuard keys must be base64 encoded") from exc
    if len(raw) != 32:
        raise ValueError("WireGuard keys must contain 32 bytes")
    return raw


def parse_wireguard(content: str) -> dict[str, str]:
    """Accept wg-quick syntax, including repeated Peer sections; never run hooks."""
    interface: dict[str, str] = {}
    peers: list[dict[str, str]] = []
    section: dict[str, str] | None = None
    seen_interface = False
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line == "[Interface]":
            if seen_interface:
                raise ValueError("A WireGuard profile must have one Interface section")
            section = interface
            seen_interface = True
        elif line == "[Peer]":
            section = {}
            peers.append(section)
        elif line.startswith("[") or section is None or "=" not in line:
            raise ValueError("Invalid WireGuard configuration")
        else:
            key, value = line.split("=", 1)
            key, value = key.strip(), value.split("#", 1)[0].strip()
            if not key or not value:
                raise ValueError("Invalid WireGuard setting")
            # Multiple addresses/DNS values may be expressed with repeated keys.
            if key in section and key in {"Address", "DNS", "AllowedIPs"}:
                section[key] += ", " + value
            elif key in section:
                raise ValueError("Duplicate WireGuard setting")
            else:
                section[key] = value
    if not seen_interface or not interface.get("PrivateKey") or not peers:
        raise ValueError("WireGuard needs an Interface private key and at least one Peer")
    private = x25519.X25519PrivateKey.from_private_bytes(_wg_key(interface["PrivateKey"]))
    if set(interface) - {"PrivateKey", "Address", "DNS", "ListenPort", "MTU", "Table", "SaveConfig"}:
        raise ValueError("WireGuard command hooks and unknown Interface settings are not supported")
    for address in interface.get("Address", "").split(","):
        if address.strip():
            try:
                ipaddress.ip_interface(address.strip())
            except ValueError as exc:
                raise ValueError("Invalid WireGuard interface address") from exc
    for peer in peers:
        if set(peer) - {"PublicKey", "PresharedKey", "AllowedIPs", "Endpoint", "PersistentKeepalive"}:
            raise ValueError("Unknown WireGuard Peer setting")
        if not peer.get("PublicKey"):
            raise ValueError("Each WireGuard peer needs a public key")
        _wg_key(peer["PublicKey"])
        if peer.get("PresharedKey"):
            _wg_key(peer["PresharedKey"])
        for allowed in peer.get("AllowedIPs", "").split(","):
            if allowed.strip():
                try:
                    ipaddress.ip_network(allowed.strip(), strict=False)
                except ValueError as exc:
                    raise ValueError("Invalid WireGuard AllowedIPs") from exc
    peer = peers[0]
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {
        "private_key": interface["PrivateKey"],
        "interface_public_key": base64.b64encode(public).decode("ascii"),
        "address": interface.get("Address", ""), "dns": interface.get("DNS", ""),
        "public_key": peer["PublicKey"], "endpoint": peer.get("Endpoint", ""),
        "allowed_ips": peer.get("AllowedIPs", ""), "preshared_key": peer.get("PresharedKey", ""),
        "persistent_keepalive": peer.get("PersistentKeepalive", ""), "config": content.strip() + "\n",
    }


def render_wireguard(data: dict[str, Any]) -> str:
    if data.get("config"):
        parse_wireguard(str(data["config"]))
        return str(data["config"])
    lines = ["[Interface]"]
    for field, key in (("private_key", "PrivateKey"), ("address", "Address"), ("dns", "DNS")):
        value = str(data.get(field, "")).strip()
        if value:
            if "\n" in value or "\r" in value:
                raise ValueError("WireGuard fields cannot contain line breaks")
            lines.append(f"{key} = {value}")
    lines.extend(["", "[Peer]"])
    for field, key in (("public_key", "PublicKey"), ("preshared_key", "PresharedKey"),
                       ("endpoint", "Endpoint"), ("allowed_ips", "AllowedIPs"),
                       ("persistent_keepalive", "PersistentKeepalive")):
        value = str(data.get(field, "")).strip()
        if value:
            if "\n" in value or "\r" in value:
                raise ValueError("WireGuard fields cannot contain line breaks")
            lines.append(f"{key} = {value}")
    config = "\n".join(lines) + "\n"
    parse_wireguard(config)
    return config


def ssh_fingerprint(public_key: str) -> str:
    serialization.load_ssh_public_key(public_key.encode("utf-8"))
    blob = base64.b64decode(public_key.split()[1], validate=True)
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")


def parse_ssh(content: str, passphrase: str | None = None) -> dict[str, str]:
    content = content.strip()
    try:
        if content.startswith(("ssh-", "ecdsa-")):
            public = serialization.load_ssh_public_key(content.encode())
            public_text = public.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
            return {"private_key": "", "public_key": public_text, "fingerprint": ssh_fingerprint(public_text), "passphrase": ""}
        password = passphrase.encode() if passphrase else None
        if "OPENSSH PRIVATE KEY" in content:
            private = serialization.load_ssh_private_key(content.encode(), password=password)
        else:
            private = serialization.load_pem_private_key(content.encode(), password=password)
        public_text = private.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
        return {"private_key": content + "\n", "public_key": public_text,
                "fingerprint": ssh_fingerprint(public_text), "passphrase": passphrase or ""}
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise ValueError("Invalid SSH key or passphrase") from exc


def generate_ssh(passphrase: str | None = None) -> dict[str, str]:
    private = ed25519.Ed25519PrivateKey.generate()
    encryption = serialization.BestAvailableEncryption(passphrase.encode()) if passphrase else serialization.NoEncryption()
    private_text = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, encryption).decode()
    public_text = private.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    return {"private_key": private_text, "public_key": public_text,
            "fingerprint": ssh_fingerprint(public_text), "passphrase": passphrase or ""}


def parse_env(content: str) -> dict[str, str]:
    # Interpolation is deliberately disabled: imported content must never read process secrets.
    # python-dotenv reports malformed lines via its logger; silence that path by validating
    # the parser's non-logging binding stream before calling dotenv_values.
    from dotenv.parser import parse_stream
    if any(binding.error for binding in parse_stream(io.StringIO(content))):
        raise ValueError("Invalid environment file")
    parsed = dotenv_values(stream=io.StringIO(content), interpolate=False)
    if not parsed or any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) or value is None for name, value in parsed.items()):
        raise ValueError("Invalid environment file")
    return {str(name): str(value) for name, value in parsed.items()}


def _record(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or not isinstance(value.get("name"), str) or not value["name"].strip():
        raise ValueError("Each imported record needs a name")
    kind = value.get("type", "note")
    if kind not in KINDS:
        raise ValueError("Unsupported secret type")
    data = value.get("data", {})
    if not isinstance(data, dict) or not all(isinstance(key, str) and isinstance(item, str) for key, item in data.items()):
        raise ValueError("Secret data must be an object of text fields")
    metadata = value.get("metadata", {})
    if not isinstance(metadata, dict):
        raise ValueError("Invalid metadata")
    return {"name": value["name"], "type": kind, "tags": value.get("tags", []),
            "expires_at": value.get("expires_at"), "metadata": metadata, "data": data}


def parse_import(format_name: str, content: str, name: str | None = None, passphrase: str | None = None) -> list[dict[str, Any]]:
    if len(content.encode("utf-8")) > MAX_IMPORT_BYTES:
        raise ValueError("Import exceeds the 8 MiB limit")
    if format_name == "json":
        try:
            values = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ValueError("Invalid JSON import") from exc
        if isinstance(values, dict) and "secrets" in values:
            values = values["secrets"]
        if not isinstance(values, list):
            raise ValueError("JSON import needs an array of secrets")
        records = [_record(value) for value in values]
    elif format_name == "csv":
        reader = csv.DictReader(io.StringIO(content))
        if not reader.fieldnames or "name" not in reader.fieldnames:
            raise ValueError("CSV import needs a name column")
        records = []
        for row in reader:
            if None in row:
                raise ValueError("Invalid CSV row")
            metadata = {key: row[key] for key in ("username", "hostname", "service", "notes") if row.get(key)}
            data = {key.removeprefix("data."): value or "" for key, value in row.items()
                    if key.startswith("data.") or key in {"password", "key", "secret", "token", "text", "url", "private_key", "public_key", "passphrase", "config", "content"}}
            records.append(_record({"name": row.get("name"), "type": row.get("type") or "login",
                                    "tags": [tag.strip() for tag in (row.get("tags") or "").split(",") if tag.strip()],
                                    "expires_at": row.get("expires_at") or None, "metadata": metadata, "data": data}))
    elif format_name == "env":
        parse_env(content)
        records = [{"name": name or "Environment", "type": "environment", "data": {"content": content}, "metadata": {}, "tags": []}]
    elif format_name == "ssh":
        data = parse_ssh(content, passphrase)
        records = [{"name": name or "Imported SSH key", "type": "ssh_key", "data": data,
                    "metadata": {"fingerprint": data["fingerprint"]}, "tags": []}]
    elif format_name == "wireguard":
        data = parse_wireguard(content)
        records = [{"name": name or "WireGuard profile", "type": "wireguard", "data": data,
                    "metadata": {"hostname": data["endpoint"], "address": data["address"]}, "tags": []}]
    else:
        raise ValueError("Unsupported import format")
    if not records or len(records) > MAX_IMPORT_RECORDS:
        raise ValueError("Import must contain between 1 and 500 records")
    return records
