"""Operator usage confirmation helpers for ethical safeguards."""

from __future__ import annotations

import base64
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

from .utils import ensure_directory


class UsageConfirmationError(RuntimeError):
    """Raised when operator usage confirmation requirements are not met."""


@dataclass(frozen=True)
class UsageConfirmationResult:
    """Metadata describing an operator confirmation event."""

    log_path: Optional[Path]
    entry_count: int


def require_usage_confirmation(
    *,
    confirm_ownership: bool,
    confirm_voluntary_key: bool,
    inputs: Sequence[Path],
    operator: Optional[str] = None,
    script_key: Optional[str] = None,
    audit_log: Optional[Path] = None,
    audit_passphrase: Optional[str] = None,
) -> UsageConfirmationResult:
    """Ensure the operator confirmed ethical usage prior to processing.

    Parameters
    ----------
    confirm_ownership:
        ``True`` when the operator confirmed they own or are authorised to
        analyse the supplied inputs.
    confirm_voluntary_key:
        ``True`` when the operator confirmed any provided keys were supplied
        voluntarily for the current session.
    inputs:
        The resolved input paths that will be processed.
    operator:
        Optional operator name to store in the confirmation log.
    script_key:
        The session key (if any) supplied for decoding.  Only its presence is
        recorded—no raw key material is persisted.
    audit_log / audit_passphrase:
        Optional encrypted log destination and passphrase used to persist the
        confirmation entry.

    Returns
    -------
    UsageConfirmationResult
        Describes the persisted confirmation entry (if any).
    """

    if not confirm_ownership:
        raise UsageConfirmationError(
            "Operator confirmation required: pass --confirm-ownership to affirm "
            "you are authorised to analyse the supplied inputs."
        )
    if not confirm_voluntary_key:
        raise UsageConfirmationError(
            "Operator confirmation required: pass --confirm-voluntary-key to affirm "
            "any keys were provided voluntarily for this session."
        )

    if audit_passphrase and not audit_log:
        raise UsageConfirmationError("--audit-passphrase requires --audit-log to be set")

    log_path: Optional[Path] = None
    entry_count = 0

    if audit_log is not None:
        log_path = audit_log.resolve()
        ensure_directory(log_path.parent)
        record = _build_confirmation_entry(inputs, operator, script_key)
        _append_confirmation_entry(log_path, record, audit_passphrase)
        entry_count = _count_log_entries(log_path)

    return UsageConfirmationResult(log_path=log_path, entry_count=entry_count)


def _build_confirmation_entry(
    inputs: Sequence[Path], operator: Optional[str], script_key: Optional[str]
) -> Dict[str, Any]:
    normalised_inputs: List[str] = [str(path.resolve()) for path in inputs]
    timestamp = time.time()
    key_meta: Dict[str, Any]
    if script_key:
        salt = os.urandom(16)
        digest = _hmac_digest(salt, script_key.encode("utf-8", "ignore"))
        key_meta = {
            "present": True,
            "salt": base64.b64encode(salt).decode("ascii"),
            "digest": digest,
        }
    else:
        key_meta = {"present": False}

    return {
        "version": 1,
        "timestamp": timestamp,
        "operator": operator or "unspecified",
        "inputs": normalised_inputs,
        "key": key_meta,
    }


def _append_confirmation_entry(
    log_path: Path, entry: Dict[str, Any], passphrase: Optional[str]
) -> None:
    payload: Dict[str, Any]
    if passphrase:
        payload = _encrypt_entry(entry, passphrase)
    else:
        payload = {"version": 1, "entry": entry}

    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True))
        handle.write("\n")


def _encrypt_entry(entry: Dict[str, Any], passphrase: str) -> Dict[str, Any]:
    salt = os.urandom(16)
    key = PBKDF2(passphrase, salt, dkLen=32, count=200_000)
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    serialised = json.dumps(entry, sort_keys=True).encode("utf-8")
    ciphertext, tag = cipher.encrypt_and_digest(serialised)
    return {
        "version": 1,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "tag": base64.b64encode(tag).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def _count_log_entries(path: Path) -> int:
    try:
        data = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return 0
    return sum(1 for line in data.splitlines() if line.strip())


def load_audit_entries(path: Path, passphrase: Optional[str] = None) -> List[Dict[str, Any]]:
    """Return decrypted confirmation entries from *path*.

    When the log contains encrypted entries, ``passphrase`` must be provided to
    decrypt them; otherwise a :class:`UsageConfirmationError` is raised.
    """

    if not path.exists():
        return []

    entries: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            payload = raw_line.strip()
            if not payload:
                continue
            data = json.loads(payload)
            if "ciphertext" in data:
                if not passphrase:
                    raise UsageConfirmationError(
                        "audit log contains encrypted entries; provide --audit-passphrase"
                    )
                entries.append(_decrypt_entry(data, passphrase))
            else:
                entry = data.get("entry")
                if isinstance(entry, dict):
                    entries.append(entry)
    return entries


def _decrypt_entry(payload: Dict[str, Any], passphrase: str) -> Dict[str, Any]:
    try:
        salt = base64.b64decode(payload["salt"])
        nonce = base64.b64decode(payload["nonce"])
        tag = base64.b64decode(payload["tag"])
        ciphertext = base64.b64decode(payload["ciphertext"])
    except Exception as exc:  # pragma: no cover - defensive guard for corrupt logs
        raise UsageConfirmationError("invalid encrypted audit entry") from exc

    key = PBKDF2(passphrase, salt, dkLen=32, count=200_000)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        serialised = cipher.decrypt_and_verify(ciphertext, tag)
    except Exception as exc:  # pragma: no cover - integrity failure
        raise UsageConfirmationError("failed to verify audit entry authenticity") from exc
    return json.loads(serialised.decode("utf-8"))


def _hmac_digest(salt: bytes, key: bytes) -> str:
    import hmac
    import hashlib

    return hmac.new(salt, key, hashlib.sha256).hexdigest()


__all__ = [
    "UsageConfirmationError",
    "UsageConfirmationResult",
    "load_audit_entries",
    "require_usage_confirmation",
]

